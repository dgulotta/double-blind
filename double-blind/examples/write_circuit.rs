use std::{fs::File, io::Write};

use double_blind::serialization::{DBGateSerializer, DBGeneratorSerializer};

fn write_data(path: &str) {
    env_logger::init();
    let data = double_blind::build_circuit();
    let mut file = File::create(path).unwrap();
    let bytes = data
        .data
        .to_bytes(&DBGateSerializer, &DBGeneratorSerializer)
        .unwrap();
    file.write(&bytes).unwrap();
}

fn write_verifier_data(path: &str) {
    env_logger::init();
    let data = double_blind::build_circuit();
    let mut file = File::create(path).unwrap();
    let bytes = data
        .data
        .verifier_data()
        .to_bytes(&DBGateSerializer)
        .unwrap();
    file.write(&bytes).unwrap();
}

fn main() {
    //print_gate_and_generator_names();
    write_verifier_data("/tmp/verifier-data");
}
