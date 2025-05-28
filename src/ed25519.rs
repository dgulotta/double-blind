use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use ssh_key::{PublicKey, SshSig, public::Ed25519PublicKey};

use super::{D, F};

pub struct Ed25519Targets;

impl Ed25519Targets {
    /// Returns the targets containing the public key.
    pub fn public_key_targets(&self) -> Vec<Target> {
        Vec::new()
    }
}

/// Returns the internal representation of the public key.  This function
/// should be consistent with `Ed25519Targets::public_key_targets`.
pub fn ed25519_key_target_data(_key: &Ed25519PublicKey) -> Vec<F> {
    Vec::new()
}

pub fn ed25519_example_public_key() -> PublicKey {
    PublicKey::from_openssh(include_str!("../test_keys/id_ed25519.pub")).unwrap()
}

pub fn ed25519_example_signature() -> SshSig {
    SshSig::from_pem(include_bytes!("../test_keys/ed25519.sig")).unwrap()
}

/// Builds the ed25519 part of the circuit.  Returns the targets containing the public
/// key and Double Blind key.
pub fn build_ed25519(_builder: &mut CircuitBuilder<F, D>) -> Ed25519Targets {
    Ed25519Targets
}

pub fn set_ed25519_targets(
    _pw: &mut PartialWitness<F>,
    _targets: &Ed25519Targets,
    _sig: &SshSig,
) -> anyhow::Result<()> {
    Ok(())
}
