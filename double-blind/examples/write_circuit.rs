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

fn main() {
    write_data("/tmp/circuit-data");
}
