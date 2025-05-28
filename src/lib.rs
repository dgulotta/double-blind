pub mod ed25519;
pub mod rsa;
pub mod serialization;

use anyhow::anyhow;
use base64::Engine;
use ed25519::{
    Ed25519Targets, build_ed25519, ed25519_example_signature, ed25519_key_target_data,
    set_ed25519_targets,
};
use num::BigUint;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use rsa::{RSATargets, build_rsa, rsa_example_signature, rsa_key_target_data, set_rsa_targets};
use sha2::Digest;
use ssh_key::{Mpint, PublicKey, SshSig, public::KeyData};

const MAX_KEY_LIMBS: usize = crate::rsa::RSA_LIMBS;
const SHA_LIMBS: usize = 512usize.div_ceil(63);

const DOUBLE_BLIND_MESSAGE: &str = "E PLURIBUS UNUM; DO NOT SHARE\n";
const DOUBLE_BLIND_NAMESPACE: &str = "double-blind.xyz";

#[derive(Debug)]
enum ProverError {
    PublicKeyNotFound,
}

#[derive(Debug)]
enum VerifierError {
    MerkleRoot,
    MessageHash,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverError::PublicKeyNotFound => {
                write!(f, "DoubleBlind key does not match any public key")
            }
        }
    }
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifierError::MerkleRoot => {
                write!(f, "Merkle roots do not match")
            }
            VerifierError::MessageHash => write!(f, "Message hash does not match"),
        }
    }
}

impl core::error::Error for ProverError {}
impl core::error::Error for VerifierError {}

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

const DEPTH: usize = 30;

pub fn split_biguint_63(x: &BigUint) -> Vec<F> {
    let n_limbs = x.bits().div_ceil(63) as usize;
    let mut ans = Vec::with_capacity(n_limbs);
    let mut it = x.iter_u64_digits();
    let mut leftover = 0;
    let mut leftover_bits = 0;
    let full_mask = (1 << 63) - 1;
    while ans.len() < n_limbs {
        if leftover_bits >= 63 {
            ans.push(F::from_canonical_u64(leftover & full_mask));
            leftover >>= 63;
            leftover_bits -= 63;
        } else {
            let low = leftover;
            leftover = it.next().unwrap_or(0);
            let high_bits = 63 - leftover_bits;
            let mask = (1 << high_bits) - 1;
            let high = leftover & mask;
            ans.push(F::from_canonical_u64(low | (high << leftover_bits)));
            leftover >>= high_bits;
            leftover_bits = 64 - high_bits;
        }
    }
    ans
}

pub fn find_public_key<'a>(
    public_keys: &'a [PublicKey],
    double_blind_key: &SshSig,
) -> Option<usize> {
    public_keys
        .iter()
        .enumerate()
        .filter_map(|(n, k)| {
            match k.verify(
                DOUBLE_BLIND_NAMESPACE,
                DOUBLE_BLIND_MESSAGE.as_bytes(),
                double_blind_key,
            ) {
                Ok(()) => Some(n),
                Err(_) => None,
            }
        })
        .next()
}

// plonky2's MerkleProof struct assumes that the depth is always ceiling(log_2(# of leaves)).
// But we want to fix the depth while allowing any number of leaves up to 2^depth.
struct MerkleProof {
    index: usize,
    item: HashOut<F>,
    siblings: Vec<HashOut<F>>,
    root: HashOut<F>,
}

fn compute_merkle_root(leaves: &[HashOut<F>], depth: usize) -> HashOut<F> {
    let mut hashes = leaves.to_vec();
    for _ in 0..depth {
        let new_hash_len = (hashes.len() + 1) / 2;
        let mut new_hashes = Vec::with_capacity(new_hash_len);
        for j in 0..new_hash_len {
            let left = hashes[2 * j];
            let right = hashes.get(2 * j + 1).copied().unwrap_or(HashOut::ZERO);
            let inputs = [
                left.elements[0],
                left.elements[1],
                left.elements[2],
                left.elements[3],
                right.elements[0],
                right.elements[1],
                right.elements[2],
                right.elements[3],
            ];
            new_hashes.push(hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs));
        }
        hashes = new_hashes;
    }
    hashes[0]
}

fn generate_merkle_proof(leaves: &[HashOut<F>], index: usize, depth: usize) -> MerkleProof {
    assert!(index < leaves.len());
    let mut hashes = leaves.to_vec();
    let mut siblings = Vec::with_capacity(depth);
    let mut i = index;
    for _ in 0..depth {
        let new_hash_len = (hashes.len() + 1) / 2;
        let mut new_hashes = Vec::with_capacity(new_hash_len);
        siblings.push(hashes.get(i ^ 1).copied().unwrap_or(HashOut::ZERO));
        for j in 0..new_hash_len {
            let left = hashes[2 * j];
            let right = hashes.get(2 * j + 1).copied().unwrap_or(HashOut::ZERO);
            let inputs = [
                left.elements[0],
                left.elements[1],
                left.elements[2],
                left.elements[3],
                right.elements[0],
                right.elements[1],
                right.elements[2],
                right.elements[3],
            ];
            new_hashes.push(hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs));
        }
        hashes = new_hashes;
        i /= 2;
    }
    MerkleProof {
        index,
        item: leaves[index],
        siblings,
        root: hashes[0],
    }
}

struct MerkleProofTarget {
    path: Vec<BoolTarget>,
    item: HashOutTarget,
    siblings: Vec<HashOutTarget>,
    root: HashOutTarget,
}

fn if_hash_out(
    builder: &mut CircuitBuilder<F, D>,
    b: BoolTarget,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: core::array::from_fn(|i| builder._if(b, x.elements[i], y.elements[i])),
    }
}

fn verify_merkle_proof(builder: &mut CircuitBuilder<F, D>, proof: &MerkleProofTarget) {
    assert!(proof.path.len() == proof.siblings.len());
    let mut item = proof.item;
    for (&p, &s) in proof.path.iter().zip(proof.siblings.iter()) {
        let left = if_hash_out(builder, p, s, item);
        let right = if_hash_out(builder, p, item, s);
        item = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
        ]);
    }
    builder.connect_hashes(item, proof.root);
}

fn add_virtual_merkle_proof(builder: &mut CircuitBuilder<F, D>, depth: usize) -> MerkleProofTarget {
    let path = (0..depth)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();
    let item = builder.add_virtual_hash();
    let siblings = builder.add_virtual_hashes(depth);
    let root = builder.add_virtual_hash();
    let proof = MerkleProofTarget {
        path,
        item,
        siblings,
        root,
    };
    verify_merkle_proof(builder, &proof);
    proof
}

fn set_merkle_proof(
    witness: &mut PartialWitness<F>,
    target: &MerkleProofTarget,
    proof: &MerkleProof,
) -> Result<(), anyhow::Error> {
    witness.set_hash_target(target.item, proof.item)?;
    for (n, (&s_t, &s)) in target
        .siblings
        .iter()
        .zip(proof.siblings.iter())
        .enumerate()
    {
        witness.set_bool_target(target.path[n], (proof.index >> n) & 1 != 0)?;
        witness.set_hash_target(s_t, s)?;
    }
    witness.set_hash_target(target.root, proof.root)
}

fn hash_public_key(k: &PublicKey) -> anyhow::Result<HashOut<F>> {
    let mut data = match k.key_data() {
        KeyData::Rsa(d) => rsa_key_target_data(d),
        KeyData::Ed25519(d) => ed25519_key_target_data(d),
        _ => return Err(anyhow!("Unsupported key type")),
    };
    data.resize(MAX_KEY_LIMBS, F::ZERO);
    Ok(hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&data))
}

fn hash_message(message: &[u8]) -> Vec<F> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(message);
    let hash_bigint = BigUint::from_bytes_le(&hasher.finalize());
    split_biguint_63(&hash_bigint)
}

fn mpint_to_biguint(x: &Mpint) -> BigUint {
    BigUint::from_bytes_be(x.as_positive_bytes().unwrap())
}

pub struct SignatureCircuitData {
    pub data: CircuitData<F, C, D>,
    use_rsa_t: BoolTarget,
    merkle_proof_t: MerkleProofTarget,
    message_hash_t: Vec<Target>,
    rsa_targets: RSATargets,
    ed25519_targets: Ed25519Targets,
}

pub fn build_circuit() -> SignatureCircuitData {
    let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());
    let zero = builder.zero();
    let use_rsa_t = builder.add_virtual_bool_target_safe();
    let rsa_targets = build_rsa(&mut builder);
    let rsa_hash_data = rsa_targets.public_key_targets();
    let ed25519_targets = build_ed25519(&mut builder);
    let ed25519_hash_data = ed25519_targets.public_key_targets();
    let user_key_t = (0..MAX_KEY_LIMBS)
        .map(|i| {
            builder._if(
                use_rsa_t,
                rsa_hash_data.get(i).copied().unwrap_or(zero),
                ed25519_hash_data.get(i).copied().unwrap_or(zero),
            )
        })
        .collect();
    let user_key_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(user_key_t);
    let merkle_proof_t = add_virtual_merkle_proof(&mut builder, DEPTH);
    builder.connect_hashes(user_key_hash, merkle_proof_t.item);
    for x in merkle_proof_t.root.elements {
        builder.register_public_input(x);
    }
    let message_hash_t = builder.add_virtual_targets(SHA_LIMBS);
    // By registering the message as a public input, we make the Fiat-Shamir challenges
    // depend on the message.
    for &limb in message_hash_t.iter() {
        builder.register_public_input(limb);
    }
    let data = builder.build();
    SignatureCircuitData {
        data,
        use_rsa_t,
        merkle_proof_t,
        message_hash_t,
        rsa_targets,
        ed25519_targets,
    }
}

pub fn generate_group_signature(
    message: &[u8],
    public_keys: &[PublicKey],
    double_blind_key: &SshSig,
    circuit: &SignatureCircuitData,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let user_key_index =
        find_public_key(public_keys, double_blind_key).ok_or(ProverError::PublicKeyNotFound)?;
    let key_data = public_keys[user_key_index].key_data();
    let hashed_public_keys_r: anyhow::Result<Vec<_>> =
        public_keys.iter().map(hash_public_key).collect();
    let hashed_public_keys = hashed_public_keys_r?;
    let merkle_proof = generate_merkle_proof(&hashed_public_keys, user_key_index, DEPTH);
    let message_hash = hash_message(message);
    let mut pw = PartialWitness::new();
    set_merkle_proof(&mut pw, &circuit.merkle_proof_t, &merkle_proof)?;
    if key_data.is_rsa() {
        set_rsa_targets(&mut pw, &circuit.rsa_targets, double_blind_key)?;
        set_ed25519_targets(
            &mut pw,
            &circuit.ed25519_targets,
            &ed25519_example_signature(),
        )?;
        pw.set_bool_target(circuit.use_rsa_t, true)?;
    } else {
        set_rsa_targets(&mut pw, &circuit.rsa_targets, &rsa_example_signature())?;
        set_ed25519_targets(&mut pw, &circuit.ed25519_targets, double_blind_key)?;
        pw.set_bool_target(circuit.use_rsa_t, false)?;
    }
    pw.set_target_arr(&circuit.message_hash_t, &message_hash)?;
    circuit.data.prove(pw)
}

pub fn write_group_signature(proof: &ProofWithPublicInputs<F, C, D>) -> String {
    let mut buf = "===BEGIN DOUBLE BLIND SIGNATURE===\n".to_string();
    let proof_bytes = proof.to_bytes();
    base64::engine::general_purpose::STANDARD.encode_string(&proof_bytes, &mut buf);
    buf.push_str("\n===END DOUBLE BLIND SIGNATURE===");
    buf
}

pub fn read_group_signature(
    sig: &str,
    common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let line = sig
        .lines()
        .nth(1)
        .ok_or_else(|| anyhow!("Signature format not recognized"))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(line)?;
    ProofWithPublicInputs::from_bytes(decoded, common_data)
}

pub fn verify_group_signature(
    message: &[u8],
    public_keys: &[PublicKey],
    data: &VerifierCircuitData<F, C, D>,
    proof: ProofWithPublicInputs<F, C, D>,
) -> Result<(), anyhow::Error> {
    let message_hash = hash_message(message);
    let hashed_public_keys_r: anyhow::Result<Vec<_>> =
        public_keys.iter().map(|k| hash_public_key(k)).collect();
    let hashed_public_keys = hashed_public_keys_r?;
    let root = compute_merkle_root(&hashed_public_keys, DEPTH);
    for (n, x) in root.elements.into_iter().enumerate() {
        if x != proof.public_inputs[n] {
            Err(VerifierError::MerkleRoot)?;
        }
    }
    for n in 0..SHA_LIMBS {
        if message_hash[n] != proof.public_inputs[n + 4] {
            Err(VerifierError::MessageHash)?;
        }
    }
    data.verify(proof)
}

#[cfg(test)]
mod test {
    use crate::{
        DEPTH, build_circuit, compute_merkle_root,
        ed25519::ed25519_example_public_key,
        generate_group_signature, hash_message, hash_public_key, read_group_signature,
        rsa::{rsa_example_public_key, rsa_example_signature},
        verify_group_signature, write_group_signature,
    };

    #[test]
    fn test_verify_signature_rsa() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [rsa_example_public_key(), ed25519_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        verify_group_signature(
            message.as_ref(),
            &public_keys,
            &circuit.data.verifier_data(),
            proof,
        )
    }

    #[test]
    fn test_verify_read_write() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [rsa_example_public_key(), ed25519_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let output = write_group_signature(&proof);
        let proof2 = read_group_signature(&output, &circuit.data.common)?;
        verify_group_signature(
            message.as_ref(),
            &public_keys,
            &circuit.data.verifier_data(),
            proof2,
        )
    }

    #[test]
    fn test_reject_wrong_public_keys_same_root() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [rsa_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let modified_public_keys = [ed25519_example_public_key()];
        assert!(
            verify_group_signature(
                message.as_ref(),
                &modified_public_keys,
                &circuit.data.verifier_data(),
                proof,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_reject_wrong_public_keys_and_root() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [rsa_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let mut proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let modified_public_keys = [ed25519_example_public_key()];
        let modified_public_key_hashes = [hash_public_key(&modified_public_keys[0]).unwrap()];
        let modified_root = compute_merkle_root(&modified_public_key_hashes, DEPTH);
        proof.public_inputs[..4].copy_from_slice(&modified_root.elements);
        assert!(
            verify_group_signature(
                message.as_ref(),
                &modified_public_keys,
                &circuit.data.verifier_data(),
                proof,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_reject_different_message_same_hash() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [rsa_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        assert!(
            verify_group_signature(
                "Goodbye!".as_ref(),
                &public_keys,
                &circuit.data.verifier_data(),
                proof,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_reject_different_message_and_hash() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let modified_message = "Goodbye!";
        let public_keys = [rsa_example_public_key()];
        let double_blind_key = rsa_example_signature();
        let circuit = build_circuit();
        let mut proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let hash = hash_message(modified_message.as_ref());
        proof.public_inputs[4..].copy_from_slice(&hash);
        assert!(
            verify_group_signature(
                modified_message.as_ref(),
                &public_keys,
                &circuit.data.verifier_data(),
                proof,
            )
            .is_err()
        );
        Ok(())
    }
}
