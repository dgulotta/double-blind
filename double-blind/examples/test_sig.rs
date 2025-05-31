use std::{fs::File, io::Write, time::Instant};

use double_blind::{
    build_circuit,
    ed25519::ed25519_example_public_key,
    generate_group_signature,
    rsa::{rsa_example_public_key, rsa_example_signature},
};

fn main() -> anyhow::Result<()> {
    let message = "Hello!";
    let public_keys = [rsa_example_public_key(), ed25519_example_public_key()];
    let double_blind_key = rsa_example_signature();
    let start_time = Instant::now();
    println!("Building circuit");
    let circuit = build_circuit();
    let build_finish_time = Instant::now();
    println!("{}", (build_finish_time - start_time).as_secs_f32());
    println!("Generating proof");
    let proof = generate_group_signature(
        message.as_ref(),
        &public_keys,
        &double_blind_key,
        &circuit,
        &None,
    )?;
    let proof_finish_time = Instant::now();
    println!("Proof len {}", proof.to_bytes().len());
    println!("{}", (proof_finish_time - build_finish_time).as_secs_f32());
    println!("Compressing proof");
    let compressed = proof.compress(
        &circuit.data.verifier_only.circuit_digest,
        &circuit.data.common,
    )?;
    let compress_finish_time = Instant::now();
    println!("Compressed len {}", compressed.to_bytes().len());
    println!(
        "{}",
        (compress_finish_time - proof_finish_time).as_secs_f32()
    );
    let mut f = File::create("/tmp/db_proof")?;
    f.write_all(&compressed.to_bytes())?;
    println!("Verifying proof");
    circuit.data.verify_compressed(compressed)?;
    let verify_finish_time = Instant::now();
    println!("{}", (verify_finish_time - proof_finish_time).as_secs_f32());
    Ok(())
}
