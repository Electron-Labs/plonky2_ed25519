use std::marker::PhantomData;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::{impl_gate_serializer, impl_generator_serializer, get_gate_tag_impl, read_gate_impl, get_generator_tag_impl, read_generator_impl};
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::util::serialization::{GateSerializer, WitnessGeneratorSerializer};
use plonky2_crypto::u32::gates::add_many_u32::{U32AddManyGate, U32AddManyGenerator};
use plonky2_crypto::u32::gates::arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator};
use plonky2_crypto::u32::gates::comparison::{ComparisonGate, ComparisonGenerator};
use plonky2_crypto::u32::gates::interleave_u32::{U32InterleaveGate, U32InterleaveGenerator};
use plonky2_crypto::u32::gates::range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator};
use plonky2_crypto::u32::gates::subtraction_u32::{U32SubtractionGate, U32SubtractionGenerator};
use plonky2_crypto::u32::gates::uninterleave_to_b32::UninterleaveToB32Gate;
use plonky2_crypto::u32::gates::uninterleave_to_u32::{UninterleaveToU32Gate, UninterleaveToU32Generator};
// generators
use plonky2::gadgets::arithmetic::EqualityGenerator;
use plonky2::gadgets::arithmetic_extension::QuotientGeneratorExtension;
use plonky2::gadgets::range_check::LowHighGenerator;
use plonky2::gadgets::split_base::BaseSumGenerator;
use plonky2::gadgets::split_join::{SplitGenerator, WireSplitGenerator};
use plonky2::gates::arithmetic_base::ArithmeticBaseGenerator;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGenerator;
use plonky2::gates::base_sum::BaseSplitGenerator;
use plonky2::gates::coset_interpolation::InterpolationGenerator;
use plonky2::gates::exponentiation::ExponentiationGenerator;
use plonky2::gates::lookup::LookupGenerator;
use plonky2::gates::lookup_table::LookupTableGenerator;
use plonky2::gates::multiplication_extension::MulExtensionGenerator;
use plonky2::gates::poseidon::PoseidonGenerator;
use plonky2::gates::poseidon_mds::PoseidonMdsGenerator;
use plonky2::gates::random_access::RandomAccessGenerator;
use plonky2::gates::reducing::ReducingGenerator;
use plonky2::gates::reducing_extension::ReducingGenerator as ReducingExtensionGenerator;
use plonky2::iop::generator::{
    ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
};
use plonky2::recursion::dummy_circuit::DummyProofGenerator;
use plonky2_crypto::biguint::BigUintDivRemGenerator;
use crate::curve::curve_types::Curve;
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::CurvePointDecompressionGenerator;
use crate::gadgets::nonnative::{NonNativeAdditionGenerator, NonNativeInverseGenerator, NonNativeMultiplicationGenerator, NonNativeSubtractionGenerator};

pub struct Ed25519GateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for Ed25519GateSerializer {
    impl_gate_serializer! {
        Ed25519GateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32InterleaveGate,
        UninterleaveToU32Gate,
        BaseSumGate<4>,
        ComparisonGate<F, D>,
        U32AddManyGate<F, D>,
        U32ArithmeticGate<F, D>,
        U32RangeCheckGate<F, D>,
        U32SubtractionGate<F, D>,
        UninterleaveToB32Gate
    }
}

pub struct Ed25519GeneratorSerializer<C, const D: usize> {
    pub _phantom: PhantomData<C>
}
impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for Ed25519GeneratorSerializer<C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        Ed25519GeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSplitGenerator<4>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        CopyGenerator,
        DummyProofGenerator<F, C, D>,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        ReducingExtensionGenerator<D>,
        SplitGenerator,
        WireSplitGenerator,
        BigUintDivRemGenerator<F, D>,
        CurvePointDecompressionGenerator<F, D, Ed25519>,
        NonNativeSubtractionGenerator<F,D,<Ed25519 as Curve>::BaseField>,
        NonNativeSubtractionGenerator<F,D,<Ed25519 as Curve>::ScalarField>,
        NonNativeMultiplicationGenerator<F,D,<Ed25519 as Curve>::BaseField>,
        NonNativeMultiplicationGenerator<F,D,<Ed25519 as Curve>::ScalarField>,
        NonNativeAdditionGenerator<F,D,<Ed25519 as Curve>::BaseField>,
        NonNativeAdditionGenerator<F,D,<Ed25519 as Curve>::ScalarField>,
        NonNativeInverseGenerator<F,D,<Ed25519 as Curve>::BaseField>,
        NonNativeInverseGenerator<F,D,<Ed25519 as Curve>::ScalarField>,
        U32ArithmeticGenerator<F, D>,
        U32SubtractionGenerator<F, D>,
        U32InterleaveGenerator,
        UninterleaveToU32Generator,
        U32AddManyGenerator<F, D>,
        ComparisonGenerator<F, D>,
        U32RangeCheckGenerator<F, D>
    }
}