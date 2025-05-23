use plonky2::{
    field::extension::Extendable,
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
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
use plonky2_rsa::gadgets::biguint::BigUintDivRemGenerator;
use plonky2_u32::gates::{
    add_many_u32::{U32AddManyGate, U32AddManyGenerator},
    arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator},
    comparison::{ComparisonGate, ComparisonGenerator},
    range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator},
};

pub struct DBGateSerializer;
pub struct DBGeneratorSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for DBGateSerializer {
    impl_gate_serializer!(DBGateSerializer,
        ArithmeticGate,
        ComparisonGate<F,D>,
        ConstantGate,
        NoopGate,
        PoseidonGate<F,D>,
        PublicInputGate,
        U32AddManyGate<F,D>,
        U32ArithmeticGate<F,D>,
        U32RangeCheckGate<F,D>
    );
}

impl<F: RichField + Extendable<D>, const D: usize> WitnessGeneratorSerializer<F, D>
    for DBGeneratorSerializer
{
    impl_generator_serializer!(DBGeneratorSerializer,
        ArithmeticBaseGenerator<F,D>,
        BigUintDivRemGenerator<F,D>,
        ComparisonGenerator<F,D>,
        ConstantGenerator<F>,
        CopyGenerator,
        PoseidonGenerator<F,D>,
        RandomValueGenerator,
        U32AddManyGenerator<F,D>,
        U32ArithmeticGenerator<F,D>,
        U32RangeCheckGenerator<F,D>
    );
}
