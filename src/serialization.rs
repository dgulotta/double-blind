use plonky2::{
    gadgets::{range_check::LowHighGenerator, split_join::WireSplitGenerator},
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
        base_sum::{BaseSplitGenerator, BaseSumGate},
        constant::ConstantGate,
        noop::NoopGate,
        poseidon::{PoseidonGate, PoseidonGenerator},
        public_input::PublicInputGate,
    },
    get_gate_tag_impl, get_generator_tag_impl, impl_gate_serializer, impl_generator_serializer,
    iop::generator::{ConstantGenerator, CopyGenerator, RandomValueGenerator},
    read_gate_impl, read_generator_impl,
    util::serialization::{GateSerializer, WitnessGeneratorSerializer},
};
use plonky2_gate_utils::{GateAdapter, RecursiveGenerator};
use plonky2_rsa::gadgets::biguint::{BigUintDivRemGenerator, ConvolutionGate};
use plonky2_u32::gates::comparison::{ComparisonGate, ComparisonGenerator};

pub struct DBGateSerializer;
pub struct DBGeneratorSerializer;

use crate::{D, F};

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

const RSA_BITS: usize = crate::rsa::BITS;

impl WitnessGeneratorSerializer<F, D> for DBGeneratorSerializer {
    impl_generator_serializer!(DBGeneratorSerializer,
        ArithmeticBaseGenerator<F,D>,
        BaseSplitGenerator<2>,
        BigUintDivRemGenerator<F,D,RSA_BITS>,
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
