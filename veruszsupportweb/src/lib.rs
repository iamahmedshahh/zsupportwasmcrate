use wasm_bindgen::prelude::*;
use serde_json;
use anyhow::{Result, anyhow};

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
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use chacha20poly1305::{AeadInPlace, KeyInit, ChaCha20Poly1305};
use rand_core::{RngCore, CryptoRng};
use hex;

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

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

fn parse_network(network_id: u32) -> Result<Network> {
    match network_id {
        0 => Ok(Network::MainNetwork),
        1 => Ok(Network::TestNetwork),
        _ => Err(anyhow!("Invalid network ID.")),
    }
}


fn internal_generate_channel_dfvk(seed: &[u8], from_id: &[u8], to_id: &[u8]) -> Result<DiversifiableFullViewingKey> {

    let ext_sk = ExtendedSpendingKey::master(seed);
    let account_sk = ext_sk.derive_child(ChildIndex::hardened(0));
    let account_sk_bytes = account_sk.to_bytes();

    let combined_data = [account_sk_bytes.as_ref(), from_id, to_id].concat();
    
    let channel_seed = Blake2bParams::new().hash_length(32).hash(&combined_data);

    let channel_master_sk = ExtendedSpendingKey::master(channel_seed.as_bytes());
    let channel_account_sk = channel_master_sk.derive_child(ChildIndex::hardened(0));
    Ok(channel_account_sk.to_diversifiable_full_viewing_key())
}

fn internal_get_symmetric_key_receiver(
    dfvk_bytes: &[u8],
    ephemeral_pk_bytes: &[u8],
) -> Result<Blake2bHash> {
    let dfvk_bytes_array: [u8; 128] = dfvk_bytes.try_into().map_err(|_| anyhow!("DFVK data must be 128 bytes long."))?;
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_bytes_array).ok_or_else(|| anyhow!("Failed to parse DFVK from bytes"))?;
    let ivk: SaplingIvk = dfvk.to_ivk(Scope::External);
    let sapling_ivk = PreparedIncomingViewingKey::new(&ivk);
    let epk_array: [u8; 32] = ephemeral_pk_bytes.try_into().map_err(|_| anyhow!("EPK must be 32 bytes"))?;
    let epk_bytes = EphemeralKeyBytes(epk_array);
    let epk = <SaplingDomain as Domain>::epk(&epk_bytes).ok_or_else(|| anyhow!("Failed to create EphemeralPublicKey"))?;
    let prepared_epk = <SaplingDomain as Domain>::prepare_epk(epk);
    let shared_secret = <SaplingDomain as Domain>::ka_agree_dec(&sapling_ivk, &prepared_epk);
    Ok(<SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes))
}

fn internal_generate_symmetric_key_sender(
    address: &Address,
    rseed_bytes: &[u8],
) -> Result<(Blake2bHash, EphemeralKeyBytes)> {
    let recipient = match address {
        Address::Sapling(addr) => addr,
        _ => return Err(anyhow!("Incompatible Address used")),
    };
    let rseed_array: [u8; 32] = rseed_bytes.try_into()?;
    let rseed = Rseed::AfterZip212(rseed_array);
    let mut dummy_rng = WasmRng;
    let note = Note::from_parts(recipient.clone(), NoteValue::from_raw(0), rseed);
    let esk = note.generate_or_derive_esk(&mut dummy_rng);
    let epk = <SaplingDomain as Domain>::ka_derive_public(&note, &esk);
    let epk_bytes = <SaplingDomain as Domain>::epk_bytes(&epk);
    let pk_d = recipient.pk_d();
    let shared_secret = <SaplingDomain as Domain>::ka_agree_enc(&esk, pk_d);
    let symmetric_key: Blake2bHash = <SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes);
    Ok((symmetric_key, epk_bytes))
}

#[wasm_bindgen]
pub fn generate_channel_keys(
    seed_hex: String,
    from_id_hex: String,
    to_id_hex: String,
    network_id: u32,
) -> Result<JsValue, JsValue> {
    let network = parse_network(network_id).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed_bytes = hex::decode(seed_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let from_id_bytes = hex::decode(from_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let to_id_bytes = hex::decode(to_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if seed_bytes.len() < 32 { return Err(JsValue::from_str("Seed must be at least 32 bytes")); }
    
    let dfvk = internal_generate_channel_dfvk(&seed_bytes, &from_id_bytes, &to_id_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);
    
    let result = serde_json::json!({
        "address": addr.encode(&network),
        "fvk": hex::encode(dfvk.to_bytes())
    });

    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_message(
    address_string: String,
    message: String,
    network_id: u32,
) -> Result<JsValue, JsValue> {
    let network = parse_network(network_id).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let addr = Address::decode(&network, &address_string)
        .ok_or_else(|| JsValue::from_str("Address is for the wrong network or invalid"))?;

    let mut rseed_bytes = [0u8; 32];
    getrandom::getrandom(&mut rseed_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let (symmetric_key, epk_bytes) = internal_generate_symmetric_key_sender(&addr, &rseed_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let cipher = ChaCha20Poly1305::new(symmetric_key.as_bytes().into());
    let nonce = chacha20poly1305::Nonce::default();
    let mut buffer = message.into_bytes();
    cipher.encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| JsValue::from_str("Encryption failed"))?;

    let result = serde_json::json!({
        "ephemeralPublicKey": hex::encode(epk_bytes.0),
        "ciphertext": hex::encode(buffer)
    });

    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_message(
    fvk_hex: String,
    ephemeral_public_key_hex: String,
    ciphertext_hex: String,
) -> Result<String, JsValue> {
    let fvk_bytes = hex::decode(fvk_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let epk_bytes = hex::decode(ephemeral_public_key_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let symmetric_key = internal_get_symmetric_key_receiver(&fvk_bytes, &epk_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
    let mut buffer = hex::decode(ciphertext_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cipher = ChaCha20Poly1305::new(symmetric_key.as_bytes().into());
    let nonce = chacha20poly1305::Nonce::default();
    
    cipher.decrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|_| JsValue::from_str("Decryption failed. Key or ciphertext may be incorrect."))?;

    String::from_utf8(buffer)
        .map_err(|_| JsValue::from_str("Failed to parse decrypted message as a UTF-8 string."))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_encryption_roundtrip() {
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("Failed to get random bytes");
        let from_id = "alice@".as_bytes();
        let to_id = "bob@".as_bytes();

        let channel_dfvk = internal_generate_channel_dfvk(&seed_bytes, from_id, to_id).unwrap();
        let dfvk_bytes = channel_dfvk.to_bytes();
        let (_d, payment_address) = channel_dfvk.default_address();
        let channel_address = Address::from(payment_address);

        let original_message = "This message is for a private channel.".to_string();

        let mut rseed_bytes = [0u8; 32];
        getrandom::getrandom(&mut rseed_bytes).unwrap();
        let (key, epk_bytes) = internal_generate_symmetric_key_sender(&channel_address, &rseed_bytes).unwrap();
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let mut buffer = original_message.clone().into_bytes();
        cipher.encrypt_in_place(&chacha20poly1305::Nonce::default(), b"", &mut buffer).unwrap();
        let ciphertext_bytes = buffer;

        let decrypted_message_bytes = {
            let key = internal_get_symmetric_key_receiver(&dfvk_bytes, &epk_bytes.0).unwrap();
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            let mut buffer = ciphertext_bytes.clone();
            cipher.decrypt_in_place(&chacha20poly1305::Nonce::default(), b"", &mut buffer).unwrap();
            buffer
        };
        let decrypted_message = String::from_utf8(decrypted_message_bytes).unwrap();

        assert_eq!(original_message, decrypted_message);
        println!("\n✅ Verus-style channel encryption/decryption roundtrip test passed!");
    }
}