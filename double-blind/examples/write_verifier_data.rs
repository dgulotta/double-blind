use std::{fs::File, io::Write};

use double_blind::serialization::DBGateSerializer;

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
    write_verifier_data("../double-blind-web/cache/verifier-data");
}
