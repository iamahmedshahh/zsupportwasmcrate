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
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use rand_core::{RngCore, CryptoRng};
use hex;
use bech32::{self, FromBase32,  ToBase32, Variant};
use ripemd::Ripemd160;
use bs58;

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

const I_ADDR_VERSION: u8 = 102; // the version byte used for all verus i-addresses, indicating their type
const VERUS_CHAIN_IADDR: &str = "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV"; // the base i-address for the native verus chain (vrsc)
const NULL_I_ADDR: &str = "i5w5MuNik5NtLcYmNzcvaoixooEebB6MGV"; // the null address used as a placeholder
const EMPTY_PARENT_HASH: [u8; 20] = [0u8; 20]; // 20 bytes of zero used as the hash for a null id

// double sha256 function which is non-standard but required for verus
fn sha256d_vec(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data); // first sha256 hash
    let h2 = Sha256::digest(&h1); // second sha256 hash applied to the result of the first
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out // returns a 32-byte hash
}

// standard hash160: sha256 then ripemd160
fn hash160_vec(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data); // computes sha256
    let rip = Ripemd160::digest(&sha); // computes ripemd160 on the sha256 output
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out // returns a 20-byte hash
}

fn encode_verus_iaddr(hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(I_ADDR_VERSION);

    // Reverse the hash to little-endian encoding for storage in i-address
    let mut hash_le = *hash;
    hash_le.reverse();
    payload.extend_from_slice(&hash_le);

    bs58::encode(payload).with_check().into_string()
}
// decodes a verus i-address from base58check format into its raw 20-byte hash160
fn decode_verus_iaddr(addr: &str) -> Result<[u8; 20]> {
    // attempts to decode the base58 string without automatically checking the checksum
    let decoded_all = bs58::decode(addr)
        .into_vec()
        .map_err(|e| anyhow!("base58 decode failed: {:?}", e))?;

    // an i-address must be 1 byte (version) + 20 bytes (hash) + 4 bytes (checksum) = 25 bytes
    if decoded_all.len() != 25 {
        return Err(anyhow!("decoded i-address has invalid length: expected 25, got {}", decoded_all.len()));
    }
    
    // separates the 21-byte payload (version+hash) from the 4-byte checksum
    let payload_len = 21;
    let payload = &decoded_all[..payload_len];
    let given_checksum = &decoded_all[payload_len..];

    // computes the expected checksum by applying double sha256 to the payload
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    let expected_checksum = &hash2[0..4];

    // verifies that the decoded checksum matches the expected checksum
    if given_checksum != expected_checksum {
        return Err(anyhow!("i-address checksum mismatch"));
    }

    // verifies the first byte is the correct i-address version (102)
    let version = payload[0];
    if version != I_ADDR_VERSION {
        return Err(anyhow!("unexpected i-address version byte: {} (expected {})", version, I_ADDR_VERSION));
    }

    // extracts the final 20-byte hash160 (which starts at index 1)
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[1..21]);

    hash.reverse(); // convert to little endian

    Ok(hash)
}


// combines two byte buffers and applies the non-standard double sha256 hash (sha256d)
fn hash_combined(buf1: &[u8], buf2: &[u8]) -> [u8; 32] {
    // concatenates the two input buffers
    let mut combined = Vec::with_capacity(buf1.len() + buf2.len());
    combined.extend_from_slice(buf1);
    combined.extend_from_slice(buf2);
    sha256d_vec(&combined) // returns the double sha256 hash of the concatenated data
}

// converts a verus id name (like 'alice@') into its deterministic 20-byte hash160
pub fn verusid_to_h160(verusid: &str) -> Result<[u8; 20]> {
    // input validation: ensures the name ends with '@'
    if !verusid.ends_with('@') {
        return Err(anyhow!("Invalid VerusID: must end with '@'"));
    }

    let trimmed = verusid.trim_end_matches('@'); // removes the trailing '@'
    if trimmed.is_empty() {
        return Err(anyhow!("Invalid VerusID: empty name before @"));
    }

    let name_lower = trimmed.to_ascii_lowercase(); // converts the id name to lowercase (c-locale)
    let name_buffer = name_lower.as_bytes();
    
    // gets the parent chain's hash (the verus chain i-address decoded)
    let mut parent_hash = decode_verus_iaddr(VERUS_CHAIN_IADDR)?;
    parent_hash.reverse();

    
    // calculates the hash of the individual name component using double sha256
    let name_hash = sha256d_vec(name_buffer); 
    
    // calculates the combined hash: hash(parent_hash | name_hash)
    let id_hash = hash_combined(&parent_hash, &name_hash);
    
    // final step: computes hash160 on the combined id_hash
    let mut result = hash160_vec(&id_hash);
    
    // reverses the final hash to little-endian, matching the daemon's internal storage format
    result.reverse();
    
    Ok(result) // this is the final, little-endian hash160 destination hash
}

// the main dispatcher for all input types
pub fn id_to_h160_bytes(id: &str) -> Result<[u8; 20]> {
    let trimmed = id.trim();

    // handles raw 40-character hex strings (already resolved hash160)
    if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(trimmed)?;
        let arr: [u8; 20] = decoded.try_into()
            .map_err(|_| anyhow!("Invalid length for hex ID"))?;
        return Ok(arr);
    }

    // handles i-address strings
    if trimmed.starts_with('i') {
        // delegates to the complex base58check decoding function
        return decode_verus_iaddr(trimmed);
    }

    // handles empty string or explicit null address constant
    if trimmed.is_empty() || trimmed == NULL_I_ADDR {
        return Ok(EMPTY_PARENT_HASH); // returns the 20-byte zero hash
    }

    // handles verus id names (must end with '@')
    if trimmed.ends_with('@') {
        // delegates to the recursive hashing logic
        return verusid_to_h160(trimmed);
    }

    // fallback error for invalid input format
    Err(anyhow!("Invalid ID format: must be hex, i-address, or VerusID ending with '@'"))
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

    // perform the same BIP-44 derivation as the main function
    let master_sk = ExtendedSpendingKey::master(&seed_bytes);
    let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
    let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(133));
    let account_sk = coin_type_key.derive_child(ChildIndex::hardened(hd_index));
    
    // serialize the derived key to bytes
    let mut sk_bytes = vec![];
    account_sk.write(&mut sk_bytes).map_err(|e| e.to_string())?;
    
    // return the hex-encoded spending key
    key_encoding::encode_sk(&account_sk)
        .map_err(|e| JsValue::from_str(&e.to_string()))
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



#[cfg(test)]
mod tests {
    use super::*;
    // NOTE: This is the correct, consistent hash value from your passing tests.
    const ALICE_EXPECTED_H160_LE: &str = "237cc65dbb032174f0133e2f450f9afb5645e715";
    const ALICE_IADDR: &str = "i5ULg5wze6A1uWGiXSoLjc9KBF1Ea6ZuGd"; // The i-address calculated from the H160 above

    #[test]
    fn test_1_verusid_name_to_hash() {
        
        let input_name = "alice@";
        
        // Raw Verus ID string.
        println!("Input: Verus ID Name: '{}'", input_name);
        
        //   GENERATE: Calculates the H160 by performing recursive double-SHA256 (SHA256D) 
        //    hashing against the base chain ID (VERUS_CHAIN_IADDR).
        let hash_result = verusid_to_h160(input_name).expect("Failed to hash Verus ID name");
        let hash_hex = hex::encode(hash_result);

        // The final standardized hash160 (Little-Endian).
        println!("Generated Hash (LE): {}", hash_hex);
        
        // Assertion confirms the Rust hashing logic is correct for this name.
        assert_eq!(hash_hex, ALICE_EXPECTED_H160_LE);
        
        // Show the output of the function used internally for the parent hash lookup
        let parent_hash = decode_verus_iaddr(VERUS_CHAIN_IADDR).expect("Failed to decode parent hash");
        println!("Internal Parent Hash (VERUS_CHAIN_IADDR): {}", hex::encode(parent_hash));
    }

    #[test]
    fn test_2_iaddress_decode_to_hash() {
        // i-Address Decode Conversion (decode_verus_iaddr) ---
        
        let input_iaddr = ALICE_IADDR;
        
        //  The Base58Check-encoded i-address string.
        println!("Input: i-Address: '{}'", input_iaddr);
        
        // GENERATE: Performs Base58Check decoding, verifies the checksum, and extracts 
        //    the raw 20-byte payload (the H160).
        let hash_result = decode_verus_iaddr(input_iaddr).expect("Failed to decode i-address");
        let hash_hex = hex::encode(hash_result);

        // The final standardized hash160 (Little-Endian).
        println!("Decoded Hash (LE): {}", hash_hex);
        
        // Assertion confirms the i-address decode logic produces the identical hash.
        assert_eq!(hash_hex, ALICE_EXPECTED_H160_LE);
        
        // Show the encoding function's output to demonstrate the roundtrip capability.
        let encoded_iaddr = encode_verus_iaddr(&hash_result);
        println!("Check: Re-encoded i-Address: {}", encoded_iaddr);
        assert_eq!(encoded_iaddr, input_iaddr);
    }
    // This test will print the 40-character LITTLE-ENDIAN hash.
    #[test]
    fn output_format_test() {
        let iaddr = "i6iAZJPTEHcH1ctBHXwEHKoN3utwr9nReH";
        let h160_le = id_to_h160_bytes(iaddr).expect("decode failed");
        
        // The output string will be the LITTLE-ENDIAN representation of the hash.
        println!("i-Address Output H160: {}", hex::encode(h160_le)); 
    }

        #[test]
    fn test_z_getencryptionaddress_core_golden_value() {

        let seed_hex = "a".repeat(64);
        let from_id = "alice@";
        let to_id = "bob@";

        // Expected Golden Outputs from Daemon Console ---
        const GOLDEN_ADDRESS: &str = "zs120e9xq89awhmvscegn9ezst7x9vt7asanwav2vaxwmlhum23peqjsrqnr6mx2lg7hmfmgy9psdy";
        const GOLDEN_IVK: &str = "ecac41f3aae79cfd212d241c2f690787234f60fd1bd9622b5321367f92502707";
        
        println!("\n=== Running Golden Value Test ===");

        let channel_keys = z_getencryptionaddress_core(RpcParams {
            seed: Some(seed_hex),
            spending_key: None,
            hd_index: 0,
            encryption_index: 0,
            from_id: Some(from_id.to_string()),
            to_id: Some(to_id.to_string()),
            return_secret: true,
        }).expect("Failed to generate channel keys");

        println!("Actual Address: {}", channel_keys.address);
        println!("Expected Address: {}", GOLDEN_ADDRESS);
        println!("Actual IVK: {}", channel_keys.ivk.as_ref().unwrap());

        // Assert the final derived address matches the daemon's output
        assert_eq!(channel_keys.address, GOLDEN_ADDRESS, "Final derived address mismatch.");
        
        //Assert the derived Incoming Viewing Key (IVK) matches the daemon's output
        assert_eq!(channel_keys.ivk.unwrap(), GOLDEN_IVK, "Derived IVK mismatch.");
    }
}