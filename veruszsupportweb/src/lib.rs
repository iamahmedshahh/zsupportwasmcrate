use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize}; // Add Serialize
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};

use sapling_crypto::{
    zip32::{ExtendedSpendingKey, DiversifiableFullViewingKey, ExtendedFullViewingKey}, 
    note_encryption::{PreparedIncomingViewingKey, SaplingDomain},
    value::NoteValue,
    Note, Rseed,
    keys:: SaplingIvk,
};
use zcash_primitives::{
    consensus::Network,
    zip32::{ChildIndex, Scope},
};
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zcash_keys::address::Address;
use blake2b_simd::{Hash as Blake2bHash};
use chacha20poly1305::{AeadInPlace, KeyInit, ChaCha20Poly1305};
use rand_core::{RngCore, CryptoRng};
use hex;
use bech32::{self, FromBase32,  ToBase32, Variant};
use ripemd::Ripemd160;


// a dummy rng passed to satisfy a function parameter requirement.
// the function's internal logic bypasses this rng because randomness is
// already provided via the note's rseed, getting used in internal_generate_symmetric_key_sender
// cannot remove because it as a parameter even though bypassed with 
struct WasmRng;
impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(0); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}
impl CryptoRng for WasmRng {}

// This makes final .wasm file significantly smaller,which helps the extension load faster in the browser
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// This makes debugging much easier with detailed error messages

#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// derives a shared symmetric key using the receiver's private viewing key
// and the sender's public key

fn internal_get_symmetric_key_receiver(
    dfvk_bytes: &[u8],
    ephemeral_pk_bytes: &[u8],
) -> Result<Blake2bHash> {

    // parse the viewing key bytes into a key object
    let dfvk_bytes_array: [u8; 128] = dfvk_bytes.try_into().map_err(|_| anyhow!("DFVK data must be 128 bytes long."))?;
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_bytes_array).ok_or_else(|| anyhow!("Failed to parse DFVK from bytes"))?;

    // extract the incoming viewing key (ivk), the private part needed for decryption
    let ivk: SaplingIvk = dfvk.to_ivk(Scope::External);
    let sapling_ivk = PreparedIncomingViewingKey::new(&ivk);

    // parse the sender's public key bytes into a key object
    let epk_array: [u8; 32] = ephemeral_pk_bytes.try_into().map_err(|_| anyhow!("EPK must be 32 bytes"))?;
    let epk_bytes = EphemeralKeyBytes(epk_array);
    let epk = <SaplingDomain as Domain>::epk(&epk_bytes).ok_or_else(|| anyhow!("Failed to create EphemeralPublicKey"))?;

    // prepare the public key
    let prepared_epk = <SaplingDomain as Domain>::prepare_epk(epk);

    // perform key agreement (ecdh) to calculate the shared secret
    let shared_secret = <SaplingDomain as Domain>::ka_agree_dec(&sapling_ivk, &prepared_epk);

    // derive the final symmetric key using the key derivation function/kdf
    Ok(<SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes))
}

// this internal function generates a symmetric key from the sender's side
// it creates a temporary, single-use key pair and uses the recipient's public
// address to establish a shared secret

fn internal_generate_symmetric_key_sender(
    address: &Address,
    rseed_bytes: &[u8],
) -> Result<(Blake2bHash, EphemeralKeyBytes)> {

    //ensures the provided address is a sapling address
    let recipient = match address {
        Address::Sapling(addr) => addr,
        _ => return Err(anyhow!("Incompatible Address used")),
    };

    // seed is a required component for creating a note, from which the
    // temporary encryption keys are derive
    let rseed_array: [u8; 32] = rseed_bytes.try_into()?;
    let rseed = Rseed::AfterZip212(rseed_array);

    // create a dummy RNG to satisfy the function signature
    // this RNG is not used in the actual key generation logic
    let mut dummy_rng = WasmRng;
    let note = Note::from_parts(recipient.clone(), NoteValue::from_raw(0), rseed);

    // generates a new, single-use ephemeral secret key
    // this is the sender's temporary private key for this one-time encryption
    let esk = note.generate_or_derive_esk(&mut dummy_rng);

    // derives the corresponding ephemeral public key
    let epk = <SaplingDomain as Domain>::ka_derive_public(&note, &esk);
    let epk_bytes = <SaplingDomain as Domain>::epk_bytes(&epk);

    //it combines the sender's esk with the
    //recipient's pk_d to compute a secret value

    let pk_d = recipient.pk_d();
    let shared_secret = <SaplingDomain as Domain>::ka_agree_enc(&esk, pk_d);

    // derives the symmetric key using the shared secret and the ephemeral public key bytes
    let symmetric_key: Blake2bHash = <SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes);
    Ok((symmetric_key, epk_bytes))
}

mod key_encoding {
    use super::*;
    const FVK_PREFIX: &str = "zxviews";
    const SK_PREFIX: &str = "secret-extended-key-main";

    pub fn encode_xfvk(xfvk: &ExtendedFullViewingKey) -> Result<String, anyhow::Error> {
        let mut serialized = Vec::with_capacity(169);
        xfvk.write(&mut serialized)?;
        bech32::encode(FVK_PREFIX, serialized.to_base32(), Variant::Bech32)
            .map_err(|e| anyhow::anyhow!("Bech32 encoding failed: {}", e))
    }

    pub fn encode_sk(sk: &ExtendedSpendingKey) -> Result<String, anyhow::Error> {
        let mut bytes = vec![];
        sk.write(&mut bytes)?;
        Ok(bech32::encode(SK_PREFIX, bytes.to_base32(), Variant::Bech32)?)
    }
}


// The `#[derive(Deserialize)]` attribute automatically generates code
// to parse a JavaScript object into this Rust struct
#[derive(Deserialize)]
struct RpcParams {
    seed: Option<String>,
    #[serde(rename = "spendingKey")]
    spending_key: Option<String>,
    #[serde(default)]
    #[serde(rename = "hdIndex")]
    hd_index: u32,
    #[serde(default)]
    #[serde(rename = "encryptionIndex")]
    encryption_index: u32,
    #[serde(default)] 
    #[serde(rename = "fromId")]
    from_id: Option<String>,
    #[serde(default)] 
    #[serde(rename = "toId")]
    to_id: Option<String>,
    #[serde(default)]
    #[serde(rename = "returnSecret")]
    return_secret: bool,
}

// The `#[derive(Serialize)]` attribute automatically generates code
// to convert this Rust struct into a JavaScript object
#[derive(Serialize)]
pub struct ChannelKeys {
    pub address: String, // z-addr, bech32 encoded
    pub fvk: String,     // Extended Full Viewing Key, bech32 encoded
    #[serde(rename = "fvkHex")]
    pub fvk_hex: String, // Extended Full Viewing Key, hex encoded
    #[serde(rename = "dfvkHex")]
    pub dfvk_hex: String,
    #[serde(rename = "spendingKey", skip_serializing_if = "Option::is_none")]
    pub spending_key: Option<String>, // Extended Spending Key, bech32 encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ivk: Option<String>, // Incoming Viewing Key, hex encoded
}
// struct for the encrypted payload
#[derive(Serialize)]
struct EncryptedPayload {
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: String,
    ciphertext: String,
    #[serde(rename = "symmetricKey", skip_serializing_if = "Option::is_none")]
    symmetric_key: Option<String>,
}

// struct for flexible decryption parameters
#[derive(Deserialize)]
struct DecryptParams {
    #[serde(rename = "fvkHex")]
    fvk_hex: Option<String>,
    #[serde(rename = "ephemeralPublicKeyHex")]
    ephemeral_public_key_hex: Option<String>,
    #[serde(rename = "ciphertextHex")]
    ciphertext_hex: String,
    #[serde(rename = "symmetricKeyHex")]
    symmetric_key_hex: Option<String>,
}

/// helper to parse an ID string into a 20-byte hash160
/// it smartly checks if the ID is already a 40-char hex string
fn id_to_h160_bytes(id: &str) -> anyhow::Result<[u8; 20]> {
    
    // iff caller provided 40 hex chars, treat as the h160 directly
    if id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = hex::decode(id)?;
        let arr: [u8; 20] = b.try_into().map_err(|_| anyhow::anyhow!("ID hex must be 20 bytes"))?;
        return Ok(arr);
    }
    // otherwise compute hash160 = RIPEMD160(SHA256(id_bytes))
    let sha = Sha256::digest(id.as_bytes());
    let rip = Ripemd160::digest(&sha);
    Ok(rip.into())
}


// derives a unique, deterministic encryption address for a communication channel
// this function is pure rust and can be unit-tested with `cargo test`.
fn z_getencryptionaddress_core(params: RpcParams) -> anyhow::Result<ChannelKeys> {
    // determine the base spending key from either a seed or a provided key
    let base_sk = if let Some(seed_hex) = params.seed {
        // if a seed is provided, derive the account key using the hd_index
        let seed_bytes = hex::decode(seed_hex)?;
        if seed_bytes.len() < 32 { return Err(anyhow::anyhow!("Seed must be at least 32 bytes")); }
        // derive base spending key using the daemon's fixed path m/32'/coin_type'/hd_index'
        let master_sk = ExtendedSpendingKey::master(&seed_bytes);
        let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
        let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(133));
        coin_type_key.derive_child(ChildIndex::hardened(params.hd_index))

    } else if let Some(sk_bech32) = params.spending_key {
        // if a spending key is provided, decode and use it directly
        let (hrp, data, _) = bech32::decode(&sk_bech32)
            .map_err(|e| anyhow::anyhow!("Invalid bech32 spending key format: {:?}", e))?;

        // validate the key's prefix
        if hrp != "secret-extended-key-main" {
            return Err(anyhow::anyhow!("Invalid spending key prefix: expected 'secret-extended-key-main', got '{}'", hrp));
        }

        // convert from bech32's internal format to raw bytes
        let sk_bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| anyhow::anyhow!("Failed to convert key data from base32: {:?}", e))?;

        // parse the raw bytes into a key object
        ExtendedSpendingKey::from_bytes(&sk_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to parse spending key from decoded bech32 bytes"))?

    } else {
        return Err(anyhow::anyhow!("Must provide 'seed' or 'spendingKey'"));
    };

    // serialize base spending key to start building the unique channel seed
    let mut base_sk_bytes = Vec::new();
    base_sk.write(&mut base_sk_bytes)?;
    let mut encryption_seed_bytes = base_sk_bytes;

    // if from_id is present, append its byte-flipped hash160
    if let Some(id_str) = params.from_id.as_ref() {
        if !id_str.is_empty() {
            let mut h160 = id_to_h160_bytes(id_str)?;
            h160.reverse(); // byte-flip to match daemon little-endian ordering
            encryption_seed_bytes.extend_from_slice(&h160);
        } else {
            encryption_seed_bytes.push(0u8);
        }
    } else {
        encryption_seed_bytes.push(0u8);
    }

    // if to_id is present, append its byte-flipped hash160
    if let Some(id_str) = params.to_id.as_ref() {
        if !id_str.is_empty() {
            let mut h160 = id_to_h160_bytes(id_str)?;
            h160.reverse(); // byte-flip to match daemon little-endian ordering
            encryption_seed_bytes.extend_from_slice(&h160);
        }
    }
    
    // hash the concatenated data to get the unique, deterministic seed for this channel
    let channel_seed: [u8; 32] = Sha256::digest(&encryption_seed_bytes).into();

    // use the channel seed to derive the final key for this channel
    // this follows the same derivation path but uses the new seed
    let channel_master_sk = ExtendedSpendingKey::master(&channel_seed);
    let channel_purpose = channel_master_sk.derive_child(ChildIndex::hardened(32));
    let channel_coin = channel_purpose.derive_child(ChildIndex::hardened(133));
    let final_sk = channel_coin.derive_child(ChildIndex::hardened(params.encryption_index));
    
    // derive all the necessary public keys and address from the final spending key
    let xfvk = final_sk.to_extended_full_viewing_key();
    let mut xfvk_bytes = Vec::with_capacity(169); 
    xfvk.write(&mut xfvk_bytes)?;

    let dfvk = final_sk.to_diversifiable_full_viewing_key();
    let network = Network::MainNetwork;
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);
    let ivk = dfvk.to_ivk(Scope::External);

    // prepare the final address and keys in the channelkeys struct to be returned
    let channel_keys = ChannelKeys {
        address: addr.encode(&network),
        fvk: key_encoding::encode_xfvk(&xfvk)?,
        fvk_hex: hex::encode(xfvk_bytes),
        dfvk_hex: hex::encode(dfvk.to_bytes()),
        spending_key: if params.return_secret {
            Some(key_encoding::encode_sk(&final_sk)?)
        } else {
            None
        },
        ivk: Some(hex::encode(ivk.0.to_bytes())),
    };

    Ok(channel_keys)
}

#[wasm_bindgen]
pub fn z_getencryptionaddress(params: JsValue) -> Result<JsValue, JsValue> {
    let params: RpcParams = serde_wasm_bindgen::from_value(params)
        .map_err(|e| JsValue::from_str(&format!("Invalid parameters: {}", e)))?;

    let channel_keys = z_getencryptionaddress_core(params)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&channel_keys)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

#[wasm_bindgen]
pub fn generate_spending_key(seed_hex: String, hd_index: u32) -> Result<String, JsValue> {
    let seed_bytes = hex::decode(seed_hex).map_err(|e| e.to_string())?;
    if seed_bytes.len() < 32 { return Err(JsValue::from_str("Seed must be at least 32 bytes")); }

    // perform the same BIP-44 derivation as your main function
    let master_sk = ExtendedSpendingKey::master(&seed_bytes);
    let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
    let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(133));
    let account_sk = coin_type_key.derive_child(ChildIndex::hardened(hd_index));
    
    // serialize the derived key to bytes
    let mut sk_bytes = vec![];
    account_sk.write(&mut sk_bytes).map_err(|e| e.to_string())?;
    
    // return the hex-encoded spending key
    Ok(hex::encode(sk_bytes))
}

#[wasm_bindgen]
pub fn encrypt_message(
    address_string: String,
    message: String,
    return_ssk: bool,
) -> Result<JsValue, JsValue> {
    let network = Network::MainNetwork;

    // decode the address string into a structured address object
    let addr = Address::decode(&network, &address_string)
        .ok_or_else(|| JsValue::from_str("Address is for the wrong network or invalid"))?;

    // generate fresh random bytes for the note's rseed
    let mut rseed_bytes = [0u8; 32];
    getrandom::getrandom(&mut rseed_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // call the internal helper to perform the key exchange
    // this returns the shared symmetric key and the public ephemeral key
    let (symmetric_key, epk_bytes) = internal_generate_symmetric_key_sender(&addr, &rseed_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // initialize the chacha20poly1305 cipher with the symmetric key
    let cipher = ChaCha20Poly1305::new(symmetric_key.as_bytes().into());
    let nonce = chacha20poly1305::Nonce::default();
    let mut buffer = message.into_bytes();

    // encrypt the message in place using the cipher and nonce
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| JsValue::from_str("Encryption failed"))?;
    
    // Return a direct JS object via a struct
    let result = EncryptedPayload {
        ephemeral_public_key: hex::encode(epk_bytes.0),
        ciphertext: hex::encode(buffer),
        // added ssk as an optional field
        symmetric_key: if return_ssk {
            Some(hex::encode(symmetric_key.as_bytes()))
        } else {
            None
        },
    };

    Ok(serde_wasm_bindgen::to_value(&result)?)
}

#[wasm_bindgen]
pub fn decrypt_message(params: JsValue) -> Result<String, JsValue> {
    // parse the incoming JS object into our DecryptParams struct
    let params: DecryptParams = serde_wasm_bindgen::from_value(params)?;

    // determine which decryption key to use.
    let symmetric_key = if let Some(ssk_hex) = params.symmetric_key_hex {
        // decrypt using the provided SSK directly
        let ssk_bytes_vec = hex::decode(ssk_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let ssk_bytes: [u8; 32] = ssk_bytes_vec.try_into().map_err(|_| JsValue::from_str("SSK must be 32 bytes"))?;
        
        // create the hash by value instead of reference
        let mut key_buffer = [0u8; 64];
        key_buffer[..32].copy_from_slice(&ssk_bytes);
        Blake2bHash::from(key_buffer)

    } else if let (Some(fvk_hex), Some(epk_hex)) = (params.fvk_hex, params.ephemeral_public_key_hex) {
        // derive the key using the FVK the normal way
        let fvk_bytes = hex::decode(fvk_hex).map_err(|e| e.to_string())?;
        let epk_bytes = hex::decode(epk_hex).map_err(|e| e.to_string())?;
        internal_get_symmetric_key_receiver(&fvk_bytes, &epk_bytes).map_err(|e| e.to_string())?
    } else {
        return Err(JsValue::from_str("Must provide either a symmetricKeyHex or both fvkHex and ephemeralPublicKeyHex"));
    };

    // decode the ciphertext hex into a mutable byte buffer for in-place decryption
    let mut buffer = hex::decode(params.ciphertext_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // initialize the chacha20poly1305 cipher with the derived key
    let cipher = ChaCha20Poly1305::new(symmetric_key.as_bytes().into());
    let nonce = chacha20poly1305::Nonce::default();

    // decrypt the buffer in place, this will fail if the key is wrong
    cipher.decrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| JsValue::from_str("Decryption failed. Key or ciphertext may be incorrect."))?;

    // convert the decrypted bytes back into a readable string
    String::from_utf8(buffer)
        .map_err(|_| JsValue::from_str("Failed to parse decrypted message as a UTF-8 string."))
}


// The z_getencryptionaddress function is now untestable with cargo test 
// because its signature used the JsValue type
// JsValue is a special type that only exists in a WebAssembly environment where JS is active. 