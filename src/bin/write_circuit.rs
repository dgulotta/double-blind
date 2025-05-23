use std::{any::Any, collections::HashSet, fs::File, io::Write};

use double_blind::serialization::{DBGateSerializer, DBGeneratorSerializer};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

fn main() {
    env_logger::init();
    let data = double_blind::build_circuit();
    /*
    let mut gate_names = HashSet::new();
    for gate in data.data.prover_only.generators {
        gate_names.insert(gate.0.id());
    }
    for name in gate_names {
        println!("{name}");
    }
    */
    let mut file = File::create("circuit-data").unwrap();
    let bytes = data
        .data
        .to_bytes(&DBGateSerializer, &DBGeneratorSerializer)
        .unwrap();
    file.write(&bytes).unwrap();
}
