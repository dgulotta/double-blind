use double_blind::{
    GroupSignature, SignatureCircuitData, build_circuit, check_key_match, generate_group_signature,
    read_group_signature, verify_group_signature, write_group_signature,
};
use ssh_key::{PublicKey, SshSig};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(getter_with_clone)]
pub struct KeyCheckResponse {
    pub public_keys_valid: Vec<u8>,
    pub double_blind_key_valid: bool,
    pub user_public_key_index: Option<usize>,
}

#[wasm_bindgen]
pub struct Test;

#[wasm_bindgen]
impl Test {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[wasm_bindgen]
    pub fn test(&self, _: usize) {}
}

#[wasm_bindgen]
pub struct Circuit(SignatureCircuitData);

fn parse_public_keys(data: &str) -> anyhow::Result<Vec<PublicKey>> {
    let keys: ssh_key::Result<Vec<_>> = data.lines().map(|l| PublicKey::from_openssh(l)).collect();
    Ok(keys?)
}

#[wasm_bindgen]
impl Circuit {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(build_circuit())
    }

    pub fn generate_signature(
        &self,
        message: &str,
        public_keys: &str,
        double_blind_key: &str,
    ) -> Result<String, String> {
        self.generate_signature_internal(message, public_keys, double_blind_key)
            .map_err(|e| e.to_string())
    }

    /// Verifies the group signature.  On success, returns the list of public keys.
    pub fn read_signature(&self, message: &str, signature: &str) -> Result<String, String> {
        self.read_signature_internal(message, signature)
            .map_err(|e| e.to_string())
    }
}

impl Circuit {
    fn generate_signature_internal(
        &self,
        message: &str,
        public_keys: &str,
        double_blind_key: &str,
    ) -> anyhow::Result<String> {
        let public_keys_parsed = parse_public_keys(public_keys)?;
        let double_blind_key_parsed = SshSig::from_pem(double_blind_key)?;
        let proof = generate_group_signature(
            message.as_ref(),
            &public_keys_parsed,
            &double_blind_key_parsed,
            &self.0,
        )?;
        let sig = GroupSignature {
            proof,
            keys: public_keys_parsed.to_vec(),
        };
        Ok(write_group_signature(&sig))
    }

    pub fn read_signature_internal(
        &self,
        message: &str,
        signature: &str,
    ) -> anyhow::Result<String> {
        let sig = read_group_signature(signature, &self.0.data.common)?;
        verify_group_signature(
            message.as_ref(),
            &sig.keys,
            &self.0.data.verifier_data(),
            sig.proof,
        )?;
        let pk_strings: Vec<_> = sig.keys.iter().map(|k| k.to_openssh().unwrap()).collect();
        Ok(pk_strings.join("\n"))
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
