use plonky2::{
    field::types::{Field, PrimeField},
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ed25519::{
    curve::{curve_types::AffinePoint, ed25519::Ed25519},
    gadgets::eddsa,
};
use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    PublicKey, SshSig,
};

pub const D: usize = 2;
pub type F = <plonky2::plonk::config::PoseidonGoldilocksConfig as
    plonky2::plonk::config::GenericConfig<D>>::F;

/// Ed25519 verification targets bundle
pub struct Ed25519Targets {
    /// EdDSA verification gadget (message/sig/pk bits)
    pub eddsa: eddsa::EDDSATargets,
    /// Public key as 8×32-bit limbs for Poseidon hashing
    pub pk_limbs: Vec<Target>,
}

impl Ed25519Targets {
    pub fn public_key_targets(&self) -> Vec<Target> {
        self.pk_limbs.clone()
    }

    pub fn signature_targets(&self) -> Vec<Target> {
        Vec::new()
    }
}

/// Convert 256 public key bits to 8×32-bit limbs
fn pk_bits_to_limbs(
    bits: &[BoolTarget],
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<Target> {
    assert_eq!(bits.len(), 256, "PK must be exactly 256 bits");

    bits.chunks(32)
        .map(|chunk| {
            let limb = builder.add_virtual_target();
            let sum = builder.le_sum(chunk.to_vec().into_iter());
            builder.connect(limb, sum);
            limb
        })
        .collect()
}

/// Decompress Ed25519 public key to field element limbs
pub fn ed25519_key_target_data(key: &Ed25519PublicKey) -> Vec<F> {
    let bytes: &[u8; 32] = key.as_ref();
    let aff: AffinePoint<Ed25519> = plonky2_ed25519::curve::eddsa::point_decompress(bytes)
        .expect("invalid Ed25519 public key");

    let mut out = Vec::new();
    for coord in [&aff.x, &aff.y] {
        for limb in coord.to_canonical_biguint().to_u32_digits() {
            out.push(F::from_canonical_u32(limb));
        }
    }
    out
}

pub fn ed25519_example_public_key() -> PublicKey {
    PublicKey::from_openssh(include_str!("../test_keys/id_ed25519.pub")).unwrap()
}

pub fn ed25519_example_signature() -> SshSig {
    SshSig::from_pem(include_bytes!("../test_keys/ed25519.sig")).unwrap()
}

/// Build Ed25519 verification circuit
pub fn build_ed25519(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_bytes: usize,
) -> Ed25519Targets {
    let eddsa_t = eddsa::make_verify_circuits(builder, msg_len_bytes);
    let pk_limbs = pk_bits_to_limbs(&eddsa_t.pk, builder);
    
    Ed25519Targets { eddsa: eddsa_t, pk_limbs }
}

pub fn is_ed25519_key_supported(_key: &Ed25519PublicKey) -> bool {
    true
}

/// Set witness values for Ed25519 verification
pub fn set_ed25519_targets(
    pw: &mut PartialWitness<F>,
    targets: &Ed25519Targets,
    message: &[u8],
    sig: &SshSig,
) -> anyhow::Result<()> {
    let pk = match sig.public_key() {
        KeyData::Ed25519(pk) => pk,
        _ => anyhow::bail!("signature does not carry an Ed25519 key"),
    };
    
    let sig_bytes = sig.signature().as_ref();
    anyhow::ensure!(sig_bytes.len() == 64, "Ed25519 signature must be 64 bytes");

    eddsa::fill_circuits::<F, D>(
        pw,
        message,
        sig_bytes,
        pk.as_ref(),
        &targets.eddsa,
    );
    Ok(())
}

/// Build SSH signed data format
pub fn build_ssh_signed_data(namespace: &str, raw_msg: &[u8], ssh_sig: &SshSig) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();

    // Namespace
    let ns_bytes = namespace.as_bytes();
    out.extend_from_slice(&(ns_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(ns_bytes);

    // Reserved field
    let reserved = ssh_sig.reserved();
    out.extend_from_slice(&(reserved.len() as u32).to_be_bytes());
    out.extend_from_slice(reserved);

    // Hash algorithm
    let hash_alg = ssh_sig.hash_alg();
    let alg_name = hash_alg.as_str().as_bytes();
    out.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
    out.extend_from_slice(alg_name);

    // Message hash
    let hash_bytes = hash_alg.digest(raw_msg);
    out.extend_from_slice(&(hash_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(hash_bytes.as_slice());

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DOUBLE_BLIND_MESSAGE, DOUBLE_BLIND_NAMESPACE};
    use plonky2::{
        field::types::PrimeField64,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2_ed25519::curve::eddsa::verify_message;
    use ssh_key::HashAlg;

    type Ff = F;

    fn example_key() -> Ed25519PublicKey {
        match &ed25519_example_public_key().key_data() {
            KeyData::Ed25519(pk) => pk.clone(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn key_target_roundtrip() {
        let pk = example_key();
        let limbs = ed25519_key_target_data(&pk);

        let limbs_per_coord = limbs.len() / 2;
        let (x_limbs, y_limbs) = limbs.split_at(limbs_per_coord);

        let to_big = |ls: &[Ff]| {
            let mut acc = num::BigUint::default();
            for (i, &limb) in ls.iter().enumerate() {
                let limb64 = limb.to_canonical_u64();
                acc |= num::BigUint::from(limb64) << (32 * i);
            }
            acc
        };

        let x = to_big(x_limbs);
        let y = to_big(y_limbs);

        let dec = plonky2_ed25519::curve::eddsa::point_decompress(pk.as_ref()).unwrap();
        assert_eq!(dec.x.to_canonical_biguint(), x);
        assert_eq!(dec.y.to_canonical_biguint(), y);
    }

    #[test]
    fn prove_and_verify() -> anyhow::Result<()> {
        let ssh_sig = ed25519_example_signature();
        let signed_data = build_ssh_signed_data(
            DOUBLE_BLIND_NAMESPACE,
            DOUBLE_BLIND_MESSAGE.as_bytes(),
            &ssh_sig,
        );

        let mut builder = CircuitBuilder::<Ff, D>::new(CircuitConfig::standard_ecc_config());
        let targets = build_ed25519(&mut builder, signed_data.len());

        type CFG = PoseidonGoldilocksConfig;
        let data = builder.build::<CFG>();

        let mut pw = PartialWitness::new();
        set_ed25519_targets(&mut pw, &targets, &signed_data, &ssh_sig)?;

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_eddsa_native_ssh_sig() {
        let sig = ed25519_example_signature();
        let pubkey = ed25519_example_public_key();

        assert!(pubkey
            .verify(
                DOUBLE_BLIND_NAMESPACE,
                DOUBLE_BLIND_MESSAGE.as_bytes(),
                &sig
            )
            .is_ok());
    }

    #[test]
    fn test_eddsa_native() {
        let ssh_sig = ed25519_example_signature();
        let pkv: &[u8; 32] = match ssh_sig.public_key() {
            KeyData::Ed25519(pk) => pk.as_ref(),
            _ => panic!("expected an Ed25519 key"),
        };

        let signed_data = build_ssh_signed_data(
            DOUBLE_BLIND_NAMESPACE,
            DOUBLE_BLIND_MESSAGE.as_bytes(),
            &ssh_sig,
        );
        let signed_data2 = SshSig::signed_data(
            DOUBLE_BLIND_NAMESPACE,
            HashAlg::Sha512,
            DOUBLE_BLIND_MESSAGE.as_bytes(),
        )
        .unwrap();

        assert_eq!(signed_data, signed_data2);

        let ok = verify_message(&signed_data, ssh_sig.signature().as_ref(), pkv);
        assert!(ok, "native Ed25519 verify_message failed");
    }
}