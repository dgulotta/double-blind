use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    gadgets::{range_check::LowHighGenerator, split_join::WireSplitGenerator},
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
        base_sum::{BaseSplitGenerator, BaseSumGate},
        constant::ConstantGate,
        noop::NoopGate,
        poseidon::{PoseidonGate, PoseidonGenerator},
        public_input::PublicInputGate,
    },
    get_gate_tag_impl, get_generator_tag_impl,
    hash::hash_types::RichField,
    impl_gate_serializer, impl_generator_serializer,
    iop::generator::{ConstantGenerator, CopyGenerator, RandomValueGenerator},
    read_gate_impl, read_generator_impl,
    util::serialization::{GateSerializer, WitnessGeneratorSerializer, gate_serialization::log},
};
use plonky2_gate_utils::{GateAdapter, RecursiveGenerator};
use plonky2_rsa::gadgets::biguint::{BigUintDivRemGenerator, ConvolutionGate};
use plonky2_u32::gates::{
    add_many_u32::{U32AddManyGate, U32AddManyGenerator},
    arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator},
    comparison::{ComparisonGate, ComparisonGenerator},
    range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator},
};

pub struct DBGateSerializer;
pub struct DBGeneratorSerializer;

type F = GoldilocksField;
const D: usize = 2;

impl GateSerializer<F, D> for DBGateSerializer {
    impl_gate_serializer!(DBGateSerializer,
        ArithmeticGate,
        BaseSumGate<2>,
        ComparisonGate<F,D>,
        ConstantGate,
        GateAdapter<F, ConvolutionGate>,
        NoopGate,
        PoseidonGate<F,D>,
        PublicInputGate
    );
}

use crate::BITS;

impl WitnessGeneratorSerializer<F, D> for DBGeneratorSerializer {
    impl_generator_serializer!(DBGeneratorSerializer,
        ArithmeticBaseGenerator<F,D>,
        BaseSplitGenerator<2>,
        BigUintDivRemGenerator<F,D,BITS>,
        ComparisonGenerator<F,D>,
        ConstantGenerator<F>,
        CopyGenerator,
        LowHighGenerator,
        PoseidonGenerator<F,D>,
        RandomValueGenerator,
        RecursiveGenerator<1,F,ConvolutionGate>,
        WireSplitGenerator
    );
}
