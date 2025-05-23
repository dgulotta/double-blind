pub mod serialization;

use std::sync::LazyLock;

use num::{BigUint, FromPrimitive};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget},
        hashing::{hash_n_to_hash_no_pad, hash_n_to_m_no_pad},
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_rsa::gadgets::{
    biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint},
    rsa::pow_65537,
};
use sha2::Digest;

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
const RSA_LIMBS: usize = 64;
const SHA_LIMBS: usize = 16;

// the 5 is just a placeholder
pub static RSA_MESSAGE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_u64(5).unwrap());
pub static PUBLIC_EXPONENT: LazyLock<BigUint> = LazyLock::new(|| BigUint::from_u64(65537).unwrap());

fn find_public_key<'a>(public_keys: &'a [BigUint], double_blind_key: &BigUint) -> Option<usize> {
    public_keys
        .iter()
        .enumerate()
        .filter_map(|(n, k)| {
            if &double_blind_key.modpow(&PUBLIC_EXPONENT, k) == &*RSA_MESSAGE {
                Some(n)
            } else {
                None
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

fn hash_biguint(x: &BigUint, limbs: usize) -> HashOut<F> {
    let digits: Vec<_> = biguint_to_limbs(x, limbs)
        .map(|x| F::from_canonical_u32(x))
        .collect();
    hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&digits)
}

fn hash_message(message: &[u8]) -> BigUint {
    let mut hasher = sha2::Sha512::new();
    hasher.update(message);
    BigUint::from_bytes_le(&hasher.finalize())
}

fn biguint_to_limbs(x: &BigUint, n_limbs: usize) -> impl Iterator<Item = u32> {
    x.iter_u32_digits()
        .chain(core::iter::repeat(0))
        .take(n_limbs)
}

pub struct SignatureCircuitData {
    pub data: CircuitData<F, C, D>,
    merkle_proof_t: MerkleProofTarget,
    double_blind_key_t: BigUintTarget,
    user_key_t: BigUintTarget,
    message_hash_t: BigUintTarget,
}

pub fn build_circuit() -> SignatureCircuitData {
    let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());
    let rsa_message_t = builder.constant_biguint(&RSA_MESSAGE);
    let double_blind_key_t = builder.add_virtual_biguint_target(RSA_LIMBS);
    let user_key_t = builder.add_virtual_biguint_target(RSA_LIMBS);
    let rsa_message_computed = pow_65537(&mut builder, &double_blind_key_t, &user_key_t);
    builder.connect_biguint(&rsa_message_t, &rsa_message_computed);
    let user_key_vec = user_key_t.limbs.iter().map(|t| t.0).collect();
    let user_key_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(user_key_vec);
    let merkle_proof_t = add_virtual_merkle_proof(&mut builder, DEPTH);
    builder.connect_hashes(user_key_hash, merkle_proof_t.item);
    for x in merkle_proof_t.root.elements {
        builder.register_public_input(x);
    }
    let message_hash_t = builder.add_virtual_biguint_target(SHA_LIMBS);
    // By registering the message as a public input, we make the Fiat-Shamir challenges
    // depend on the message.
    for limb in message_hash_t.limbs.iter() {
        builder.register_public_input(limb.0);
    }
    let data = builder.build();
    SignatureCircuitData {
        data,
        merkle_proof_t,
        double_blind_key_t,
        user_key_t,
        message_hash_t,
    }
}

pub fn generate_group_signature(
    message: &[u8],
    public_keys: &[BigUint],
    double_blind_key: &BigUint,
    circuit: &SignatureCircuitData,
) -> Result<ProofWithPublicInputs<F, C, D>, anyhow::Error> {
    let user_key_index =
        find_public_key(public_keys, double_blind_key).ok_or(ProverError::PublicKeyNotFound)?;
    let hashed_public_keys: Vec<_> = public_keys
        .iter()
        .map(|k| hash_biguint(k, RSA_LIMBS))
        .collect();
    let merkle_proof = generate_merkle_proof(&hashed_public_keys, user_key_index, DEPTH);
    let message_hash = hash_message(message);
    let mut pw = PartialWitness::new();
    set_merkle_proof(&mut pw, &circuit.merkle_proof_t, &merkle_proof)?;
    pw.set_biguint_target(&circuit.double_blind_key_t, &double_blind_key)?;
    pw.set_biguint_target(&circuit.user_key_t, &public_keys[user_key_index])?;
    pw.set_biguint_target(&circuit.message_hash_t, &message_hash)?;
    circuit.data.prove(pw)
}

pub fn verify_group_signature(
    message: &[u8],
    public_keys: &[BigUint],
    data: &VerifierCircuitData<F, C, D>,
    proof: ProofWithPublicInputs<F, C, D>,
) -> Result<(), anyhow::Error> {
    let message_hash = hash_message(message);
    let hashed_public_keys: Vec<_> = public_keys
        .iter()
        .map(|k| hash_biguint(k, RSA_LIMBS))
        .collect();
    let root = compute_merkle_root(&hashed_public_keys, DEPTH);
    for (n, x) in root.elements.into_iter().enumerate() {
        if x != proof.public_inputs[n] {
            Err(VerifierError::MerkleRoot)?;
        }
    }
    for (n, x) in biguint_to_limbs(&message_hash, SHA_LIMBS).enumerate() {
        if F::from_canonical_u32(x) != proof.public_inputs[n + 4] {
            Err(VerifierError::MessageHash)?;
        }
    }
    data.verify(proof)
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use num::{BigUint, FromPrimitive, Num};
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    use crate::{
        DEPTH, RSA_LIMBS, RSA_MESSAGE, build_circuit, compute_merkle_root,
        generate_group_signature, hash_biguint, hash_message, verify_group_signature,
    };

    const MODULUS_STR: &str = "a709e2f84ac0e21eb0caa018cf7f697f774e96f8115fc2359e9cf60b1dd8d4048d974cdf8422bef6be3c162b04b916f7ea2133f0e3e4e0eee164859bd9c1e0ef0357c142f4f633b4add4aab86c8f8895cd33fbf4e024d9a3ad6be6267570b4a72d2c34354e0139e74ada665a16a2611490debb8e131a6cffc7ef25e74240803dd71a4fcd953c988111b0aa9bbc4c57024fc5e8c4462ad9049c7f1abed859c63455fa6d58b5cc34a3d3206ff74b9e96c336dbacf0cdd18ed0c66796ce00ab07f36b24cbe3342523fd8215a8e77f89e86a08db911f237459388dee642dae7cb2644a03e71ed5c6fa5077cf4090fafa556048b536b879a88f628698f0c7b420c4b7";
    const PRIVATE_KEY_STR: &str = "10f22727e552e2c86ba06d7ed6de28326eef76d0128327cd64c5566368fdc1a9f740ad8dd221419a5550fc8c14b33fa9f058b9fa4044775aaf5c66a999a7da4d4fdb8141c25ee5294ea6a54331d045f25c9a5f7f47960acbae20fa27ab5669c80eaf235a1d0b1c22b8d750a191c0f0c9b3561aaa4934847101343920d84f24334d3af05fede0e355911c7db8b8de3bf435907c855c3d7eeede4f148df830b43dd360b43692239ac10e566f138fb4b30fb1af0603cfcf0cd8adf4349a0d0b93bf89804e7c2e24ca7615e51af66dccfdb71a1204e2107abbee4259f2cac917fafe3b029baf13c4dde7923c47ee3fec248390203a384b9eb773c154540c5196bce1";
    static MODULUS: LazyLock<BigUint> =
        LazyLock::new(|| BigUint::from_str_radix(MODULUS_STR, 16).unwrap());
    static PRIVATE_KEY: LazyLock<BigUint> =
        LazyLock::new(|| BigUint::from_str_radix(PRIVATE_KEY_STR, 16).unwrap());

    #[test]
    fn test_verify_signature() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [MODULUS.clone(), BigUint::from_u64(5).unwrap()];
        let double_blind_key = RSA_MESSAGE.modpow(&PRIVATE_KEY, &MODULUS);
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
    fn test_reject_wrong_public_keys_same_root() -> Result<(), anyhow::Error> {
        let message = "Hello!";
        let public_keys = [MODULUS.clone(), BigUint::from_u64(5).unwrap()];
        let double_blind_key = RSA_MESSAGE.modpow(&PRIVATE_KEY, &MODULUS);
        let circuit = build_circuit();
        let proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let modified_public_keys = [BigUint::from_u64(5).unwrap()];
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
        let public_keys = [MODULUS.clone(), BigUint::from_u64(5).unwrap()];
        let double_blind_key = RSA_MESSAGE.modpow(&PRIVATE_KEY, &MODULUS);
        let circuit = build_circuit();
        let mut proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let modified_public_keys = [BigUint::from_u64(5).unwrap()];
        let modified_public_key_hashes = [hash_biguint(&modified_public_keys[0], RSA_LIMBS)];
        let modified_root = compute_merkle_root(&modified_public_key_hashes, DEPTH);
        for (i, &x) in modified_root.elements.iter().enumerate() {
            proof.public_inputs[i] = x;
        }
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
        let public_keys = [MODULUS.clone()];
        let double_blind_key = RSA_MESSAGE.modpow(&PRIVATE_KEY, &MODULUS);
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
        let public_keys = [MODULUS.clone()];
        let double_blind_key = RSA_MESSAGE.modpow(&PRIVATE_KEY, &MODULUS);
        let circuit = build_circuit();
        let mut proof =
            generate_group_signature(message.as_ref(), &public_keys, &double_blind_key, &circuit)?;
        let hash = hash_message(modified_message.as_ref());
        for (i, x) in hash.iter_u32_digits().enumerate() {
            proof.public_inputs[i + 4] = GoldilocksField::from_canonical_u32(x);
        }
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
