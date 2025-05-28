/*
use std::{any::Any, collections::BTreeSet, fs::File, io::Write};

use double_blind::serialization::{DBGateSerializer, DBGeneratorSerializer};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

fn print_gate_and_generator_names() {
    let data = double_blind::build_circuit();
    let mut gate_names = BTreeSet::new();
    for gate in data.data.common.gates.iter() {
        gate_names.insert(gate.0.id());
    }
    for name in gate_names {
        println!("{name}");
    }
    println!("");
    let mut generator_names = BTreeSet::new();
    for generator in data.data.prover_only.generators.iter() {
        generator_names.insert(generator.0.id());
    }
    for name in generator_names {
        println!("{name}");
    }
}

fn write_data() {
    env_logger::init();
    let data = double_blind::build_circuit();
    let mut file = File::create("circuit-data").unwrap();
    let bytes = data
        .data
        .to_bytes(&DBGateSerializer, &DBGeneratorSerializer)
        .unwrap();
    file.write(&bytes).unwrap();
}
*/

fn main() {
    //print_gate_and_generator_names();
    // write_data()
}
