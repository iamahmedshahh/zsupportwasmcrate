use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize}; // Add Serialize
use anyhow::{Result, anyhow};
use sha2::{Sha256, Digest};

use sapling_crypto::{
    zip32::{ExtendedSpendingKey, DiversifiableFullViewingKey}, 
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
    #[serde(rename = "fromId")]
    from_id: String,
    #[serde(rename = "toId")]
    to_id: String,
}

// The `#[derive(Serialize)]` attribute automatically generates code
// to convert this Rust struct into a JavaScript object
#[derive(Serialize)]
struct ChannelKeys {
    address: String,
    fvk: String,
}

// struct for the encrypted payload
#[derive(Serialize)]
struct EncryptedPayload {
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: String,
    ciphertext: String,

    // adding optional parameter
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


#[wasm_bindgen]
pub fn z_getencryptionaddress(params: JsValue) -> Result<JsValue, JsValue> {

    // parse the incoming javascript object into the rpcparams struct
    let params: RpcParams = serde_wasm_bindgen::from_value(params)?;

    // determine the base spending key from either a seed or a provided key
    let base_sk = if let Some(seed_hex) = params.seed {

        // if a seed is provided, derive the account key using the hd_index

        let seed_bytes = hex::decode(seed_hex).map_err(|e| e.to_string())?;
        let master_sk = ExtendedSpendingKey::master(&seed_bytes);
        master_sk.derive_child(ChildIndex::hardened(params.hd_index))

    } else if let Some(sk_hex) = params.spending_key {

        // if a spending key is provided, decode and use it directly
        let sk_bytes = hex::decode(sk_hex).map_err(|e| e.to_string())?;
        let sk_bytes_array: [u8; 169] = sk_bytes.try_into().map_err(|_| "Invalid spending key length")?;
        ExtendedSpendingKey::from_bytes(&sk_bytes_array).map_err(|_| "Failed to parse spending key")?
    } else {
        return Err(JsValue::from_str("Must provide 'seed' or 'spendingKey'"));
    };
    // decode id strings into bytes
    let from_id_bytes = hex::decode(params.from_id).map_err(|e| e.to_string())?;
    let to_id_bytes = hex::decode(params.to_id).map_err(|e| e.to_string())?;

    // hash the derived base key with the fromid and toid using sha256
    let mut hasher = Sha256::default();
    let mut base_sk_bytes = vec![];
    base_sk.write(&mut base_sk_bytes).map_err(|e| e.to_string())?;
    hasher.update(&base_sk_bytes);
    hasher.update(from_id_bytes);
    hasher.update(to_id_bytes);

    // here is our unique, deterministic seed for the communication channel;
    let channel_seed: [u8; 32] = hasher.finalize().into();

    // use the new channel seed to derive the final key for this channel
    // using the `encryption_index`
    let channel_master_sk = ExtendedSpendingKey::master(&channel_seed);
    let final_sk = channel_master_sk.derive_child(ChildIndex::hardened(params.encryption_index));

     // get the view-only key (dfvk) from the final spending key
    let dfvk = final_sk.to_diversifiable_full_viewing_key();


    let network = Network::MainNetwork;
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);

    // prepare the final address and fvk in the channelkeys struct to be returned
    let channel_keys = ChannelKeys {
        address: addr.encode(&network),
        fvk: hex::encode(dfvk.to_bytes()),
    };

    //back to js deserialized
    Ok(serde_wasm_bindgen::to_value(&channel_keys)?)
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