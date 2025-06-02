use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2::field::types::{Field, PrimeField};
use plonky2_ed25519::{
    curve::{curve_types::AffinePoint, ed25519::Ed25519},
    gadgets::{curve::AffinePointTarget, eddsa},
};

use ssh_key::{
    public::{Ed25519PublicKey, KeyData},
    PublicKey, SshSig,
};

/// — type aliases used by the surrounding codebase —
pub const D: usize = 2;
pub type F = <plonky2::plonk::config::PoseidonGoldilocksConfig as
              plonky2::plonk::config::GenericConfig<D>>::F;
// ----------------------------------------------------

/// Bundle returned by `build_ed25519`
pub struct Ed25519Targets {
    /// Complete EdDSA‐verification gadget (message / sig / pk bits)
    pub eddsa: eddsa::EDDSATargets,
    /// 8×32‐bit “limbs” = decompressed public key in unsigned‐32‐bit format,
    /// exactly aligned for Poseidon hashing / Merkle leaves.
    pub pk_limbs: Vec<Target>,
}

impl Ed25519Targets {
    /// These 8 limbs (32‐bit each) are what the outer circuit will hash.
    pub fn public_key_targets(&self) -> Vec<Target> {
        self.pk_limbs.clone()
    }
}

/// For each 32‐bit chunk of the 256 public‐key bits, allocate a fresh
/// virtual‐field‐element “limb” and constrain it = Σ b_i·2^i.
/// In other words, we do:
///   limb = add_virtual_target()
///   sum  = le_sum([...32 BoolTarget...])
///   connect(limb, sum)
/// That ensures no virtual target is ever “written twice.”
fn pk_bits_to_limbs(
    bits:    &[BoolTarget],
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<Target> {
    assert_eq!(bits.len(), 256, "PK must be exactly 256 bits");

    bits.chunks(32)
        .map(|chunk| {
            // (1) allocate a fresh field‐element limb()
            let limb = builder.add_virtual_target();

            // (2) compute Σ b_i·2^i over those 32 BoolTarget bits
            let sum  = builder.le_sum(chunk.to_vec().into_iter());

            // (3) enforce limb = sum
            builder.connect(limb, sum);

            limb
        })
        .collect()
}

/// Given an Ed25519PublicKey (32 bytes, little‐endian), decompress on CPU
/// to (x,y).  Then output 64 bytes → two 256‐bit field elements → broken
/// into 32‐bit limbs in little‐endian order.  This must match pk_limbs above.
pub fn ed25519_key_target_data(key: &Ed25519PublicKey) -> Vec<F> {
    // 1. get raw 32 bytes (little‐endian)
    let bytes: &[u8; 32] = key.as_ref();

    // 2. decompress into (x, y) ∈ Ed25519’s base field
    let aff: AffinePoint<Ed25519> =
        plonky2_ed25519::curve::eddsa::point_decompress(bytes)
            .expect("invalid Ed25519 public key");

    // 3. split x and y each into eight 32‐bit uint limbs
    let mut out = Vec::<F>::new();
    for coord in [&aff.x, &aff.y] {
        for limb in coord.to_canonical_biguint().to_u32_digits() {
            out.push(F::from_canonical_u32(limb));
        }
    }
    out
}

// ---- “demo” helpers to load the built‐in test key/signature ---------------

/// Returns the OpenSSH‐encoded Ed25519 public key from `test_keys/id_ed25519.pub`.
pub fn ed25519_example_public_key() -> PublicKey {
    PublicKey::from_openssh(include_str!("../test_keys/id_ed25519.pub")).unwrap()
}

/// Returns a PEM‐encoded Ed25519 signature from `test_keys/ed25519.sig`.
pub fn ed25519_example_signature() -> SshSig {
    SshSig::from_pem(include_bytes!("../test_keys/ed25519.sig")).unwrap()
}

/// Construct the EdDSA‐verification sub‐circuit + the 8 “pk limbs”.
pub fn build_ed25519(
    builder       : &mut CircuitBuilder<F, D>,
    msg_len_bytes : usize,
) -> Ed25519Targets {
    // (1) Let plonky2_ed25519’s make_verify_circuits allocate all bit‐targets & constraints
    let eddsa_t = eddsa::make_verify_circuits(builder, msg_len_bytes);

    // (2) Track the 256‐bit pk, break it into eight 32‐bit limbs
    let pk_limbs = pk_bits_to_limbs(&eddsa_t.pk, builder);

    Ed25519Targets { eddsa: eddsa_t, pk_limbs }
}

/// We claim every Ed25519PublicKey “is supported” (i.e. any key_data parser error
/// should be filtered earlier). Return true for now.
pub fn is_ed25519_key_supported(_key: &Ed25519PublicKey) -> bool {
    true
}

/// Fill the EdDSA‐gadget’s message bits, signature bits, and public‐key bits
/// into the PartialWitness. We pull out exactly what plonky2_ed25519 expects.
pub fn set_ed25519_targets(
    pw      : &mut PartialWitness<F>,
    targets : &Ed25519Targets,
    message : &[u8],     // raw message bytes
    sig     : &SshSig,
) -> anyhow::Result<()> {
    // (1) Ensure that `sig` actually carries an Ed25519PublicKey
    let pk = match sig.public_key() {
        KeyData::Ed25519(pk) => pk,
        _ => anyhow::bail!("signature does not carry an Ed25519 key"),
    };
    // (2) Grab the raw 64‐byte signature from SshSig
    let sig_bytes = sig.signature().as_ref();
    anyhow::ensure!(sig_bytes.len() == 64, "Ed25519 signature must be 64 bytes");

    // (3) Delegate to the “fill_circuits” helper from plonky2_ed25519
    eddsa::fill_circuits::<F, D>(
        pw,
        message,
        sig_bytes,
        pk.as_ref(),
        &targets.eddsa,
    );
    Ok(())
}

/// ----------------------------------------------------------------------------
/// Rebuild exactly the same “SignedData” bytes that SSH concatenates
/// when it performs `SignedData::to_bytes()` before signing under Ed25519.
///
/// SSH’s internal logic (in ssh-key) does something like:
///
///   let signed_data = SignedData {
///       namespace: self.namespace.as_str(),
///       reserved:  self.reserved.as_slice(),
///       hash_alg:  self.hash_alg,
///       hash:      self.hash_alg.digest(msg).as_slice(),
///   }.to_bytes()?;
///
/// That expands to:
///   b"SSHSIG"
/// ∥ u32_be(namespace.len())     ∥ namespace
/// ∥ u32_be(reserved.len())      ∥ reserved
/// ∥ u32_be(hash_alg_name.len()) ∥ hash_alg_name
/// ∥ u32_be(hash_bytes.len())    ∥ hash_bytes
///
/// where each “u32_be(…) ∥ X” is the classic SSH “string X” format
/// (4-byte big-endian length + bytes).
///
pub fn build_ssh_signed_data(namespace: &str, raw_msg: &[u8], ssh_sig: &SshSig) -> Vec<u8> {
    // (1) Literal ASCII tag "SSHSIG"
    let mut out = b"SSHSIG".to_vec();

    // (2) namespace:
    let ns_bytes = namespace.as_bytes();
    let mut len4 = (ns_bytes.len() as u32).to_be_bytes();
    out.extend_from_slice(&len4);
    out.extend_from_slice(ns_bytes);

    // (3) reserved field (usually zero length for Ed25519):
    let reserved: &[u8] = ssh_sig.reserved();
    len4 = (reserved.len() as u32).to_be_bytes();
    out.extend_from_slice(&len4);
    out.extend_from_slice(reserved);

    // (4) hash algorithm name (for Ed25519 it’s always SHA-512):
    let hash_alg = ssh_sig.hash_alg();
    let alg_name = hash_alg.as_str().as_bytes(); // e.g. b"sha512"
    len4 = (alg_name.len() as u32).to_be_bytes();
    out.extend_from_slice(&len4);
    out.extend_from_slice(alg_name);

    // (5) the SHA-512 digest of the raw message:
    let hash_bytes = hash_alg.digest(raw_msg);
    len4 = ((hash_bytes.len()) as u32).to_be_bytes();
    out.extend_from_slice(&len4);
    out.extend_from_slice(hash_bytes.as_slice());

    out
}
/// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::{DOUBLE_BLIND_MESSAGE, DOUBLE_BLIND_NAMESPACE};

    use super::*;
    use plonky2::{
        field::types::PrimeField64, iop::witness::PartialWitness, plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, VerifierCircuitData},
            config::PoseidonGoldilocksConfig,
        }
    };
    use plonky2_ed25519::curve::eddsa::verify_message;
    use ssh_key::HashAlg;

    type Cfg = PoseidonGoldilocksConfig;
    type Ff  = F;

    /// Helper to extract the Ed25519PublicKey (x,y) from the demo PublicKey.
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

        // Reconstruct the bigints (x,y) from our 32‐bit limbs
        let limbs_per_coord = limbs.len() / 2;
        let (x_limbs, y_limbs) = limbs.split_at(limbs_per_coord);

        let mut to_big = |ls: &[Ff]| {
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
        // 1) Build the same “signed_data” blob that ssh_key would have signed.
        //
        //    SSH’s Ed25519 code signs
        //
        //      string namespace
        //   ∥  string reserved
        //   ∥  string hash_alg_name
        //   ∥  string hash_bytes
        //
        //    where each “string X” is “u32_be(len(X)) ∥ X’s bytes.”  In ssh‐key crate,
        //    that is produced by SignedData { namespace, reserved, hash_alg, hash }.to_bytes().
        //
        //    We reconstruct it explicitly here.
        let ssh_sig = ed25519_example_signature();

        // (a) namespace
        let namespace = DOUBLE_BLIND_NAMESPACE.as_bytes();

        // (b) reserved field (usually zero‐length for Ed25519)
        let reserved: &[u8] = ssh_sig.reserved();

        // (c) which hash algorithm did SSH use (for Ed25519 it’s always SHA512)
        let hash_alg = ssh_sig.hash_alg();
        let hash_alg_name = hash_alg.as_str().as_bytes();

        // (d) “hash_bytes” = hash_alg.digest(raw_message)
        let raw_msg = DOUBLE_BLIND_MESSAGE.as_bytes();
        let hash_bytes = hash_alg.digest(raw_msg);

        // Build the 4‐byte‐BE length prefixes
        fn u32_be(n: usize) -> [u8; 4] {
            (n as u32).to_be_bytes()
        }

        // Now concatenate exactly:
        //   u32_be(namespace.len()) ∥ namespace
        // ∥ u32_be(reserved.len())  ∥ reserved
        // ∥ u32_be(hash_alg_name.len()) ∥ hash_alg_name
        // ∥ u32_be(hash_bytes.len())   ∥ hash_bytes
        let signed_data = build_ssh_signed_data(DOUBLE_BLIND_NAMESPACE, DOUBLE_BLIND_MESSAGE.as_bytes(), &ssh_sig);

        // 2) Now build a circuit whose “message‐length” is exactly signed_data.len().
        let mut builder = CircuitBuilder::<Ff, D>::new(CircuitConfig::standard_ecc_config());
        let targets = build_ed25519(&mut builder, signed_data.len());

        // 3) Finalize the circuit
        type CFG = PoseidonGoldilocksConfig;
        let data = builder.build::<CFG>();

        // 4) Populate PartialWitness with (signed_data, signature_bytes, public‐key)
        let mut pw = PartialWitness::new();
        set_ed25519_targets(&mut pw, &targets, &signed_data, &ssh_sig)?;

        // 5) Prove and verify; this should now succeed without partition errors.
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_eddsa_native_ssh_sig() {
        let sig = ed25519_example_signature();
        let pubkey = ed25519_example_public_key();

        // This is how ssh_key expects you to verify an Ed25519 signature:
        assert!(pubkey.verify(
            DOUBLE_BLIND_NAMESPACE,
            DOUBLE_BLIND_MESSAGE.as_bytes(),
            &sig
        ).is_ok());
    }



    #[test]
    fn test_eddsa_native() {
        // 1) Load the SSH‐signature, which carries both
        //    - the 64‐byte Ed25519 signature
        //    - the 32‐byte raw public key (KeyData::Ed25519)
        let ssh_sig = ed25519_example_signature();
    
        // 2) Pull out exactly those 32 bytes of public‐key material.
        //    `ssh_sig.public_key()` returns a `&KeyData`.  In our case,
        //    it must be KeyData::Ed25519(pk), so we can call `as_ref()` to get &[u8;32].
        let pkv: &[u8; 32] = match ssh_sig.public_key() {
            KeyData::Ed25519(pk) => pk.as_ref(),
            _ => panic!("expected an Ed25519 key"),
        };
    
        // 3) Pull out exactly those 64 bytes of raw signature.
        let sig_bytes = ssh_sig.signature().as_ref();

        // (a) the namespace under which SSH signed this payload:
        let namespace = DOUBLE_BLIND_NAMESPACE.as_bytes();
        // (b) the “reserved” field in the SshSig (typically zero‐length):
        let reserved: &[u8] = ssh_sig.reserved();
    
        // (c) which hash algorithm was used internally by the SshSig?
        //     We can ask:
        let hash_alg = ssh_sig.hash_alg();
        //     That will be something like HashAlg::Sha512.
        //     We must serialize it as a string, e.g. b"sha512"
        let hash_alg_name = hash_alg.as_str().as_bytes();
    
        // (d) “hash” = hash_alg.digest(message)
        //     In other words, if you sign M under Ed25519, you first do SHA512(M).
        let message = DOUBLE_BLIND_MESSAGE.as_bytes();
        let hash_bytes = hash_alg.digest(message);

        println!("namespace: {:?}", namespace);
        println!("reserved: {:?}", reserved);
        println!("hash_alg_name: {:?}",  hash_alg.as_str());
        println!("hash_alg_name: {:?}",  hash_alg.as_str().as_bytes());
        println!("hash_bytes: {:?}", hash_bytes.as_slice());
    

        let signed_data = build_ssh_signed_data(DOUBLE_BLIND_NAMESPACE, DOUBLE_BLIND_MESSAGE.as_bytes(), &ssh_sig);
        let signed_data2 = SshSig::signed_data(DOUBLE_BLIND_NAMESPACE, HashAlg::Sha512, DOUBLE_BLIND_MESSAGE.as_bytes()).unwrap();

        assert_eq!(signed_data, signed_data2);
    
        // Finally, feed *that exact blob* into plonky2_ed25519’s low‐level verify_message:
        let ok = verify_message(&signed_data, sig_bytes, pkv);
        assert!(ok, "native‐Ed25519 verify_message failed on signed_data");
    }

}

