use wasm_bindgen::prelude::*;
use serde_json;
use anyhow::{Result, anyhow};

use sapling_crypto::{
    zip32::{ExtendedSpendingKey, DiversifiableFullViewingKey},
    note_encryption::{PreparedIncomingViewingKey, SaplingDomain},
    value::NoteValue,
    Note, Rseed,
    keys::SaplingIvk,
};
use zcash_primitives::{
    consensus::Network,
    zip32::{ChildIndex, Scope},
};
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zcash_keys::address::Address;
use blake2b_simd::Hash as Blake2bHash;

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

// --- Internal logic functions because some functions should be done natively so they do not panic ---

fn internal_generate_dfvk(seed: &[u8]) -> Result<DiversifiableFullViewingKey> {
    let ext_sk = ExtendedSpendingKey::master(seed);
    let account_sk = ext_sk.derive_child(ChildIndex::hardened(0));
    Ok(account_sk.to_diversifiable_full_viewing_key())
}

fn internal_get_symmetric_key_receiver(
    dfvk_bytes: &[u8],
    ephemeral_pk_bytes: &[u8],
) -> Result<Blake2bHash> {
    let dfvk_bytes_array: [u8; 128] = dfvk_bytes.try_into()
        .map_err(|_| anyhow!("DFVK data must be 128 bytes long."))?;
        
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_bytes_array)
        .ok_or_else(|| anyhow!("Failed to parse DFVK from bytes"))?;

    let ivk: SaplingIvk = dfvk.to_ivk(Scope::External);
    let sapling_ivk = PreparedIncomingViewingKey::new(&ivk);

    let epk_array: [u8; 32] = ephemeral_pk_bytes.try_into().map_err(|_| anyhow!("EPK must be 32 bytes"))?;
    let epk_bytes = EphemeralKeyBytes(epk_array);

    let epk = <SaplingDomain as Domain>::epk(&epk_bytes)
        .ok_or_else(|| anyhow!("Failed to create EphemeralPublicKey"))?;

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

// --- WASM-Exported functions use some internal functions ---

#[wasm_bindgen]
pub fn generate_sapling_address_from_seed(seed_hex: &str, network_id: u32) -> Result<String, JsValue> {
    let network = parse_network(network_id).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = hex::decode(seed_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if seed.len() < 32 { return Err(JsValue::from_str("Seed must be at least 32 bytes")); }

    let dfvk = internal_generate_dfvk(&seed).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);
    Ok(addr.encode(&network))
}

#[wasm_bindgen]
pub fn generate_sapling_fvk_from_seed(seed_hex: &str, _network_id: u32) -> Result<String, JsValue> {
    let seed = hex::decode(seed_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if seed.len() < 32 { return Err(JsValue::from_str("Seed must be at least 32 bytes")); }
    
    let dfvk = internal_generate_dfvk(&seed).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(dfvk.to_bytes()))
}

#[wasm_bindgen]
pub fn get_symmetric_key_receiver_wasm(
    fvk_hex: String,
    ephemeral_pk_bytes: &[u8],
    _network_id: u32,
) -> Result<String, JsValue> {
    let fvk_bytes = hex::decode(fvk_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let symmetric_key = internal_get_symmetric_key_receiver(&fvk_bytes, ephemeral_pk_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(symmetric_key.as_bytes()))
}

#[wasm_bindgen]
pub fn generate_symmetric_key_sender_wasm(
    sapling_address_string: String,
    rseed_bytes: &[u8],
    network_id: u32,
) -> Result<JsValue, JsValue> {
    let network = parse_network(network_id).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let addr = Address::decode(&network, &sapling_address_string)
        .ok_or_else(|| JsValue::from_str("Address is for the wrong network or invalid"))?;
    
    let (symmetric_key, epk_bytes) = internal_generate_symmetric_key_sender(&addr, rseed_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "symmetric_key": hex::encode(symmetric_key.as_bytes()),
        "ephemeral_public_key": hex::encode(epk_bytes.0)
    });
    Ok(JsValue::from_str(&result.to_string()))
}


// --- Test will pass because it uses native rust functions ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_symmetric_key_test_passes() {
        let mut seed_bytes = [0u8; 32];
        getrandom::getrandom(&mut seed_bytes).expect("Failed to get random bytes");

        let dfvk = internal_generate_dfvk(&seed_bytes).unwrap();
        let dfvk_bytes = dfvk.to_bytes();
        
        let (_diversifier, payment_address) = dfvk.default_address();
        let address = Address::from(payment_address);
        
        let mut rseed_bytes = [0u8; 32];
        getrandom::getrandom(&mut rseed_bytes).expect("Failed to get random rseed bytes");

        let (sender_key, epk_bytes) =
            internal_generate_symmetric_key_sender(&address, &rseed_bytes).unwrap();

        let receiver_key =
            internal_get_symmetric_key_receiver(&dfvk_bytes, &epk_bytes.0).unwrap();

        assert_eq!(sender_key, receiver_key);
        println!("\n Native Rust test passed: Sender and Receiver keys match!");
    }
}