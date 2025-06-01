//! src/ed25519.rs   ❶ adjust the path as appropriate


use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2::field::types::{Field, PrimeField};               // <- bring helper traits in
use plonky2_ed25519::{
    curve::{curve_types::AffinePoint, ed25519::Ed25519},
    gadgets::{
        curve::{AffinePointTarget, CircuitBuilderCurve},
    },
};

use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    PublicKey, SshSig,
};

/// —— type aliases used by the surrounding codebase ———————————————
pub const D: usize = 2;       
pub type F = <plonky2::plonk::config::PoseidonGoldilocksConfig as
              plonky2::plonk::config::GenericConfig<D>>::F;
/// ————————————————————————————————————————————————————————————————

// ───────────── data that the rest of the program can keep handles to ──────────
#[derive(Clone, Debug /*, Serialize, Deserialize */)]           // <- drop Serde for now
pub struct Ed25519Targets {
    pub pub_key: AffinePointTarget<Ed25519>,
}

impl Ed25519Targets {
    pub fn public_key_targets(&self) -> Vec<Target> {
        self.pub_key
            .to_vec()
            .into_iter()
            .flat_map(|nn| nn.value.limbs)
            .map(|u32t| u32t.0)
            .collect()
    }
}

/// Convert an *actual* Ed25519 public‑key to the field elements expected in the
/// witness.  (The limb layout must match the logic in `public_key_targets`.)
pub fn ed25519_key_target_data(key: &Ed25519PublicKey) -> Vec<F> {
    // 1. raw bytes (little‑endian)
    let bytes: &[u8; 32] = key.as_ref();                      // <- API change

    // 2. CPU‑side decompression
    let affine: AffinePoint<Ed25519> =
        plonky2_ed25519::curve::eddsa::point_decompress(bytes)
            .expect("invalid Ed25519 public key");

    // 3. serialise limbs
    let mut limbs = Vec::<F>::new();
    for coord in [&affine.x, &affine.y] {
        for limb in coord.to_canonical_biguint().to_u32_digits() {
            limbs.push(F::from_canonical_u32(limb));
        }
    }
    limbs
}

// ───────────── convenience helpers for tests / demo code ─────────────────────
pub fn ed25519_example_public_key() -> PublicKey {
    PublicKey::from_openssh(include_str!("../test_keys/id_ed25519.pub")).unwrap()
}
pub fn ed25519_example_signature() -> SshSig {
    SshSig::from_pem(include_bytes!("../test_keys/ed25519.sig")).unwrap()
}

// ───────────── circuit construction —─────────────────────────────────────────
pub fn build_ed25519(builder: &mut CircuitBuilder<F, D>) -> Ed25519Targets {
    let bytes: Vec<BoolTarget> = (0..256)
        .map(|_| BoolTarget::new_unsafe(builder.add_virtual_target()))
        .collect();

    let pub_key = builder.point_decompress::<Ed25519>(&bytes);
    builder.curve_assert_valid(&pub_key);

    Ed25519Targets { pub_key }
}


pub fn is_ed25519_key_supported(_key: &Ed25519PublicKey) -> bool {
    true
}

/// Fill the witness with concrete values.

pub fn set_ed25519_targets(
    pw: &mut PartialWitness<F>,
    targets: &Ed25519Targets,
    sig: &SshSig,
) -> anyhow::Result<()> {
    // `public_key()` → &KeyData
    let pk = match sig.public_key() {
        KeyData::Ed25519(pk) => pk,
        _ => anyhow::bail!("signature does not carry an Ed25519 key"),
    };

    let data = ed25519_key_target_data(pk);
    let t    = targets.public_key_targets();
    assert_eq!(t.len(), data.len());

    for (target, value) in t.into_iter().zip(data) {
        pw.set_target(target, value);
    }
    Ok(())
}