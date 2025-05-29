use std::collections::BTreeSet;

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

fn main() {
    print_gate_and_generator_names();
}
