use double_blind::{SignatureCircuitData, build_circuit, check_key_match};
use ssh_key::{PublicKey, SshSig};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(getter_with_clone)]
pub struct KeyCheckResponse {
    pub public_keys_valid: Vec<u8>,
    pub double_blind_key_valid: bool,
    pub user_public_key_index: Option<usize>,
}

#[wasm_bindgen]
pub struct Circuit(SignatureCircuitData);

#[wasm_bindgen]
impl Circuit {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(build_circuit())
    }
}

#[wasm_bindgen]
pub fn validate_keys(public_keys: &str, double_blind_key: &str) -> KeyCheckResponse {
    let db_key = SshSig::from_pem(double_blind_key);
    let mut user_public_key_index = None;
    let public_keys_valid = public_keys
        .lines()
        .enumerate()
        .map(|(n, l)| {
            if let Ok(pk) = &PublicKey::from_openssh(l) {
                if let Ok(sig) = &db_key {
                    if check_key_match(pk, sig) {
                        user_public_key_index = Some(n);
                    }
                }
                1
            } else {
                0
            }
        })
        .collect();
    KeyCheckResponse {
        public_keys_valid,
        double_blind_key_valid: db_key.is_ok(),
        user_public_key_index,
    }
}
