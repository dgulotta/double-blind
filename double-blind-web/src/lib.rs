use std::rc::Rc;

use anyhow::anyhow;
use double_blind::{
    C, D, F, GroupSignature, NONCE_END, NONCE_START, NULLIFIER_END, NULLIFIER_START,
    SignatureCircuitData, USE_NULLIFIER_INDEX, build_circuit, check_key_match,
    generate_group_signature, read_group_signature, serialization::DBGateSerializer,
    verify_group_signature, write_group_signature,
};
use plonky2::{field::types::Field, plonk::circuit_data::VerifierCircuitData};
use ssh_key::{PublicKey, SshSig};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(getter_with_clone)]
pub struct KeyCheckResponse {
    pub public_keys_valid: Vec<u8>,
    pub double_blind_key_valid: bool,
    pub user_public_key_index: Option<usize>,
}

#[wasm_bindgen]
pub struct Circuit(Rc<SignatureCircuitData>);

#[wasm_bindgen]
pub struct Prover(Rc<SignatureCircuitData>);

#[wasm_bindgen]
pub struct Verifier(VerifierCircuitData<F, C, D>);

#[wasm_bindgen]
pub struct Signature(GroupSignature);

fn parse_public_keys(data: &str) -> anyhow::Result<Vec<PublicKey>> {
    let keys: ssh_key::Result<Vec<_>> = data.lines().map(|l| PublicKey::from_openssh(l)).collect();
    Ok(keys?)
}

#[wasm_bindgen]
impl Circuit {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Rc::new(build_circuit()))
    }

    #[deprecated]
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
    #[deprecated]
    pub fn read_signature(&self, message: &str, signature: &str) -> Result<String, String> {
        self.read_signature_internal(message, signature)
            .map_err(|e| e.to_string())
    }

    pub fn prover(&self) -> Prover {
        Prover(self.0.clone())
    }

    pub fn verifier(&self) -> Verifier {
        Verifier(self.0.data.verifier_data())
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
            &None,
        )?;
        let sig = GroupSignature {
            proof,
            keys: public_keys_parsed.to_vec(),
        };
        Ok(write_group_signature(&sig))
    }

    fn read_signature_internal(&self, message: &str, signature: &str) -> anyhow::Result<String> {
        Ok(Verifier(self.0.data.verifier_data())
            .read_signature_internal(message, signature)?
            .public_keys()
            .join("\n"))
    }
}

#[wasm_bindgen]
impl Verifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let bytes = include_bytes!("../cache/verifier-data");
        Verifier(VerifierCircuitData::from_bytes(bytes.to_vec(), &DBGateSerializer).unwrap())
    }

    pub fn read_signature(&self, message: &str, signature: &str) -> Result<Signature, String> {
        self.read_signature_internal(message, signature)
            .map_err(|e| e.to_string())
    }
}

impl Verifier {
    fn read_signature_internal(&self, message: &str, signature: &str) -> anyhow::Result<Signature> {
        let sig = read_group_signature(signature, &self.0.common)?;
        verify_group_signature(
            message.as_ref(),
            &sig.keys,
            &self.0,
            sig.proof.clone(),
            &None,
        )?;
        Ok(Signature(sig))
    }
}

#[wasm_bindgen]
impl Prover {
    /// Generate a signature without a nullifier.
    pub fn generate_signature(
        &self,
        message: &str,
        public_keys: &str,
        double_blind_key: &str,
    ) -> Result<Signature, String> {
        self.generate_signature_internal(message, public_keys, double_blind_key, None)
            .map_err(|e| e.to_string())
    }

    /// Generate a signature with a nullifier.
    /// The nonce should be 32 bytes long.
    pub fn generate_signature_with_nullifier(
        &self,
        message: &str,
        public_keys: &str,
        double_blind_key: &str,
        nonce: Vec<u8>,
    ) -> Result<Signature, String> {
        self.generate_signature_internal(message, public_keys, double_blind_key, Some(nonce))
            .map_err(|e| e.to_string())
    }
}

fn nonce_bytes_to_field(bytes: Vec<u8>) -> anyhow::Result<[F; 5]> {
    if bytes.len() != 32 {
        return Err(anyhow!("Nonce should contain 32 bytes."));
    }
    let mut ans = [0u64; 5];
    for i in 0..32 {
        ans[i / 7] |= (bytes[i] as u64) << ((i % 7) * 8);
    }
    Ok(ans.map(F::from_canonical_u64))
}

fn field_to_nonce_bytes(nonce: &[F]) -> Vec<u8> {
    (0..32)
        .map(|i| (nonce[i / 7].0 >> (i % 7) * 8) as u8)
        .collect()
}

impl Prover {
    fn generate_signature_internal(
        &self,
        message: &str,
        public_keys: &str,
        double_blind_key: &str,
        nonce: Option<Vec<u8>>,
    ) -> anyhow::Result<Signature> {
        let public_keys_parsed = parse_public_keys(public_keys)?;
        let double_blind_key_parsed = SshSig::from_pem(double_blind_key)?;
        let proof = generate_group_signature(
            message.as_ref(),
            &public_keys_parsed,
            &double_blind_key_parsed,
            &self.0,
            &nonce.map(nonce_bytes_to_field).transpose()?,
        )?;
        let sig = GroupSignature {
            proof,
            keys: public_keys_parsed.to_vec(),
        };
        Ok(Signature(sig))
    }
}

#[wasm_bindgen]
impl Signature {
    pub fn signature(&self) -> String {
        write_group_signature(&self.0)
    }
    pub fn public_keys(&self) -> Vec<String> {
        self.0
            .keys
            .iter()
            .map(|k| k.to_openssh().unwrap())
            .collect()
    }
    pub fn has_nullifier(&self) -> bool {
        self.0.proof.public_inputs[USE_NULLIFIER_INDEX] != F::ZERO
    }
    pub fn nullifier(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32);
        for e in &self.0.proof.public_inputs[NULLIFIER_START..NULLIFIER_END] {
            v.extend(&e.0.to_le_bytes());
        }
        v
    }
    pub fn nonce(&self) -> Vec<u8> {
        field_to_nonce_bytes(&self.0.proof.public_inputs[NONCE_START..NONCE_END])
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

#[cfg(test)]
mod test {
    use ssh_key::rand_core::{OsRng, RngCore};

    use crate::{field_to_nonce_bytes, nonce_bytes_to_field};

    #[test]
    fn test_nonce_conversion() {
        let mut nonce = vec![0; 32];
        OsRng.fill_bytes(&mut nonce);
        let forward = nonce_bytes_to_field(nonce.clone()).unwrap();
        let backward = field_to_nonce_bytes(&forward);
        assert_eq!(&nonce, &backward);
    }
}
