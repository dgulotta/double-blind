use std::{fs::File, io::Write};

use double_blind::serialization::{DBGateSerializer, DBGeneratorSerializer};

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

fn main() {
    //print_gate_and_generator_names();
    write_data()
}
