/*
use plonky2::field::goldilocks_field::GoldilocksField;

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
*/
