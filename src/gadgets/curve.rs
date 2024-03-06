//modified from:= https://github.com/mir-protocol/plonky2-ecdsa/blob/main/src/gadgets/curve.rs
use std::marker::PhantomData;
use std::str::FromStr;

use num::BigUint;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_crypto::biguint::{GeneratedValuesBigUint, BigUintTarget};
use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2::util::serialization::{Read, Write};
use plonky2_crypto::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar};
use crate::curve::ed25519::mul_naive;
use crate::curve::eddsa::point_decompress;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::gadgets::split_nonnative::CircuitBuilderSplit;
use crate::gadgets::eddsa::biguint_to_bits_target;

const WINDOW_SIZE: usize = 4;

/// A Target representing an affine point on the curve `C`. We use incomplete arithmetic for efficiency,
/// so we assume these points are not zero.
#[derive(Clone, Debug, Default)]
pub struct AffinePointTarget<C: Curve> {
    pub x: NonNativeTarget<C::BaseField>,
    pub y: NonNativeTarget<C::BaseField>,
}

impl<C: Curve> AffinePointTarget<C> {
    pub fn to_vec(&self) -> Vec<NonNativeTarget<C::BaseField>> {
        vec![self.x.clone(), self.y.clone()]
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> plonky2::util::serialization::IoResult<()> {
        self.x.value.serialize(dst)?;
        self.y.value.serialize(dst)
    }

    pub fn deserialize(src: &mut plonky2::util::serialization::Buffer) -> plonky2::util::serialization::IoResult<Self> {
        let x_biguint_target = BigUintTarget::deserialize(src)?;
        let x = NonNativeTarget::<C::BaseField> {
            value: x_biguint_target,
            _phantom: PhantomData,
        };
        let y_biguint_target = BigUintTarget::deserialize(src)?;
        let y = NonNativeTarget::<C::BaseField> {
            value: y_biguint_target,
            _phantom: PhantomData,
        };
        Ok(Self {x, y})
    }
}

pub trait CircuitBuilderCurve<F: RichField + Extendable<D>, const D: usize> {
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C>;

    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    );

    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C>;

    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>);

    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;

    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;

    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;

    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C>;

    /// Add two points, which are assumed to be non-equal.
    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C>;

    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;

    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C>;

    fn point_compress<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> Vec<BoolTarget>;

    fn point_decompress<C: Curve>(&mut self, p: &Vec<BoolTarget>) -> AffinePointTarget<C>;

    fn random_access_curve_points<C: Curve>(&mut self, access_index: Target, v: Vec<AffinePointTarget<C>>) -> AffinePointTarget<C>;

    fn precompute_wnaf_window<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> Vec<AffinePointTarget<C>>;

    fn curve_scalar_mul_windowed<C: Curve>(&mut self, p: &AffinePointTarget<C>, n: &NonNativeTarget<C::ScalarField>) -> AffinePointTarget<C>;

    fn precompute_comb_array<C: Curve>(&mut self) -> Vec<AffinePointTarget<C>>;

    fn fixed_base_curve_scalar_mul_comb<C:Curve>(&mut self, n: &Vec<BoolTarget>) -> AffinePointTarget<C>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCurve<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C> {
        // TODO: Why not zero here?
        // debug_assert!(!point.zero);
        AffinePointTarget {
            x: self.constant_nonnative(point.x),
            y: self.constant_nonnative(point.y),
        }
    }

    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    ) {
        self.connect_nonnative(&lhs.x, &rhs.x);
        self.connect_nonnative(&lhs.y, &rhs.y);
    }

    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C> {
        let x = self.add_virtual_nonnative_target();
        let y = self.add_virtual_nonnative_target();

        AffinePointTarget { x, y }
    }

    // A * x^2 + y^2 = 1 + D * x^2* y^2
    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>) {
        let a = self.constant_nonnative(C::A);
        let d = self.constant_nonnative(C::D);

        let x_sq = self.mul_nonnative(&p.x, &p.x);
        let y_sq = self.mul_nonnative(&p.y, &p.y);
        let a_xsq = self.mul_nonnative(&a, &x_sq);
        let one = self.constant_nonnative(C::BaseField::ONE);
        let x_sq_y_sq = self.mul_nonnative(&x_sq, &y_sq);
        let d_x_sq_y_sq = self.mul_nonnative(&d, &x_sq_y_sq);

        let lhs = self.add_nonnative(&a_xsq, &y_sq);
        let rhs = self.add_nonnative(&one, &d_x_sq_y_sq);
        self.connect_nonnative(&lhs, &rhs);
    }

    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        let neg_x = self.neg_nonnative(&p.x);
        AffinePointTarget {
            x: neg_x,
            y: p.y.clone(),
        }
    }

    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: self.nonnative_conditional_neg(&p.x, b),
            y: p.y.clone(),
        }
    }

    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        let x_sq = self.mul_nonnative(&p.x, &p.x);
        let y_sq = self.mul_nonnative(&p.y, &p.y);
        let x_y = self.mul_nonnative(&p.x, &p.y);
        let two_x_y = self.add_nonnative(&x_y, &x_y);
        let d = self.constant_nonnative(C::D);
        let a = self.constant_nonnative(C::A);

        let x_sq_y_sq = self.mul_nonnative(&x_sq, &y_sq);

        let d_x_sq_y_sq = self.mul_nonnative(&d, &x_sq_y_sq);
        let a_x_sq = self.mul_nonnative(&a, &x_sq);

        let one = self.constant_nonnative(C::BaseField::ONE);
        let two = self.constant_nonnative(C::BaseField::TWO);

        let y_sq_a_x_sq = self.sub_nonnative(&y_sq, &a_x_sq);

        let x3_denom = self.add_nonnative(&one, &d_x_sq_y_sq);
        let a_x_sq_plus_y_sq = self.add_nonnative(&a_x_sq, &y_sq);
        let y3_denom = self.sub_nonnative(&two, &a_x_sq_plus_y_sq);

        let x3_denom_inv = self.inv_nonnative(&x3_denom);
        let y3_denom_inv = self.inv_nonnative(&y3_denom);

        let x3 = self.mul_nonnative(&two_x_y, &x3_denom_inv);
        let y3 = self.mul_nonnative(&y_sq_a_x_sq, &y3_denom_inv);

        AffinePointTarget {
            x: x3,
            y: y3
        }
    }

    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C> {
        let mut result = p.clone();

        for _ in 0..n {
            result = self.curve_double(&result);
        }

        result
    }

    /// Generic point addition formulae:
    /// x3 = (x1y2+y1x2)/(1+dx1x2y1y2)
    /// y3 = (y1y2+x1x2)/(1-dx1x2y1y2)
    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C> {
        // let AffinePointTarget { x: x1, y: y1 } = p1;
        // let AffinePointTarget { x: x2, y: y2 } = p2;
        let one_constant = self.constant_nonnative(C::BaseField::ONE);
        let d_constant = self.constant_nonnative(C::D);

        let x_term = self.mul_nonnative(&p1.x, &p2.y);
        let y_term = self.mul_nonnative(&p1.y, &p2.x);
        let sum_xy_terms = self.add_nonnative(&x_term, &y_term);

        let both_y = self.mul_nonnative(&p1.y, &p2.y);
        let both_x = self.mul_nonnative(&p1.x, &p2.x);
        let sum_both_terms = self.add_nonnative(&both_y, &both_x);

        let xy_product = self.mul_nonnative(&x_term, &y_term);
        let scaled_xy_product = self.mul_nonnative(&d_constant, &xy_product);
        let neg_scaled_xy_product = self.neg_nonnative(&scaled_xy_product);

        let top_sum = self.add_nonnative(&one_constant, &scaled_xy_product);
        let bottom_sum = self.add_nonnative(&one_constant, &neg_scaled_xy_product);

        let inv_top_sum = self.inv_nonnative(&top_sum);
        let inv_bottom_sum = self.inv_nonnative(&bottom_sum);

        let x3 = self.mul_nonnative(&sum_xy_terms, &inv_top_sum);
        let y3 = self.mul_nonnative(&sum_both_terms, &inv_bottom_sum);

        AffinePointTarget { x: x3, y: y3 }
    }

    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        let not_b = self.not(b);
        let sum = self.curve_add(p1, p2);
        let x_if_true = self.mul_nonnative_by_bool(&sum.x, b);
        let y_if_true = self.mul_nonnative_by_bool(&sum.y, b);
        let x_if_false = self.mul_nonnative_by_bool(&p1.x, not_b);
        let y_if_false = self.mul_nonnative_by_bool(&p1.y, not_b);

        let x = self.add_nonnative(&x_if_true, &x_if_false);
        let y = self.add_nonnative(&y_if_true, &y_if_false);

        AffinePointTarget { x, y }
    }

    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C> {
        self.curve_scalar_mul_windowed(p, n)
    }


    fn point_compress<C: Curve>(&mut self, point: &AffinePointTarget<C>) -> Vec<BoolTarget> {
        let mut point_y_bits = biguint_to_bits_target::<F, D, 2>(self, &point.y.value);
        let low_x_bits = self.split_le_base::<2>(point.x.value.get_limb(0).0, 32);

        let bit_a = point_y_bits[0].target.clone();
        let bit_b = low_x_bits[0];

        // Compute bitwise or

        let a_add_b = self.add(bit_a, bit_b);
        let ab = self.mul(bit_a, bit_b);
        point_y_bits[0] = BoolTarget::new_unsafe(self.sub(a_add_b, ab));
        point_y_bits
    }

    fn point_decompress<C: Curve>(&mut self, compressed_point: &Vec<BoolTarget>) -> AffinePointTarget<C> {
        assert_eq!(compressed_point.len(), 256);
        let new_point = self.add_virtual_affine_point_target();

        self.add_simple_generator(CurvePointDecompressionGenerator::<F, D, C> {
            compressed: compressed_point.clone(),
            new_point: new_point.clone(),
            _phantom: PhantomData,
        });

        let decompressed = self.point_compress(&new_point);
        for i in 0..256 {
            self.connect(compressed_point[i].target, decompressed[i].target);
        }
        new_point
    }

    fn random_access_curve_points<C: Curve>(&mut self, access_index: Target, v: Vec<AffinePointTarget<C>>) -> AffinePointTarget<C> {
        let num_limbs = C::BaseField::BITS / 32;
        let zero = self.zero_u32();
        let x_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| {
                v.iter()
                    .map(|p| p.x.value.limbs.get(i).unwrap_or(&zero).0)
                    .collect()
            })
            .collect();
        let y_limbs: Vec<Vec<_>> = (0..num_limbs)
            .map(|i| {
                v.iter()
                    .map(|p| p.y.value.limbs.get(i).unwrap_or(&zero).0)
                    .collect()
            })
            .collect();

        let selected_x_limbs: Vec<_> = x_limbs
            .iter()
            .map(|limbs| U32Target(self.random_access(access_index, limbs.clone())))
            .collect();
        let selected_y_limbs: Vec<_> = y_limbs
            .iter()
            .map(|limbs| U32Target(self.random_access(access_index, limbs.clone())))
            .collect();

        let x = NonNativeTarget {
            value: BigUintTarget {
                limbs: selected_x_limbs,
            },
            _phantom: PhantomData,
        };
        let y = NonNativeTarget {
            value: BigUintTarget {
                limbs: selected_y_limbs,
            },
            _phantom: PhantomData,
        };
        AffinePointTarget { x, y }
    }

    fn precompute_wnaf_window<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> Vec<AffinePointTarget<C>> {
        let big_one = <C as Curve>::ScalarField::from_noncanonical_biguint(
            BigUint::from_str(
                "1",
            )
            .unwrap(),
        );
        let init = (CurveScalar(big_one) * C::GENERATOR_PROJECTIVE).to_affine();
        let init_target = self.constant_affine_point(init.clone());
        let init_neg_target = self.curve_neg(&init_target);
        let mut precompute =  vec![init_target];
        for i in 1..1<<WINDOW_SIZE {
            precompute.push(self.curve_add(&precompute[i-1], p));
        }
        for i in 1..1<<WINDOW_SIZE {
            precompute[i] = self.curve_add(&precompute[i], &init_neg_target);
        }
        precompute
    }

    fn curve_scalar_mul_windowed<C: Curve>(&mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C> {
        let num_limbs = C::ScalarField::BITS / 4;
        let windows = &self.split_nonnative_to_4_bit_limbs(&n)[0..num_limbs];
        let big_one = <C as Curve>::ScalarField::from_noncanonical_biguint(
            BigUint::from_str(
                "1",
            )
            .unwrap(),
        );
        let init = (CurveScalar(big_one) * C::GENERATOR_PROJECTIVE).to_affine();

        let init_multiplied = {
            let mut cur = init;
            for _ in 0..(num_limbs * 4) {
                cur = cur.double();
            }
            cur
        };

        let precompute = self.precompute_wnaf_window(p);

        let mut result = self.constant_affine_point(init.clone());
        let zero = self.zero();
        for i in (0..windows.len()).rev() {
            result = self.curve_double(&result);
            result = self.curve_double(&result);
            result = self.curve_double(&result);
            result = self.curve_double(&result);

            let window = windows[i];
            let precomp = self.random_access_curve_points(window, precompute.clone());
            let is_zero = self.is_equal(window, zero);
            let should_add = self.not(is_zero);
            result = self.curve_conditional_add(&result, &precomp, should_add);
        }
        let init_multiplied_point = self.constant_affine_point(init_multiplied.clone());
        let neg_r = self.curve_neg(&init_multiplied_point);
        result = self.curve_add(&result, &neg_r);
        result
    }

    fn precompute_comb_array<C: Curve>(&mut self) -> Vec<AffinePointTarget<C>> {
        let d: u32 =64;
        let mut precomp_array: Vec<AffinePoint<C>> = vec![C::GENERATOR_AFFINE]; // pushing generator only at 0 for now
        let mut precomp_array_target = vec![];
        for i in 1..16 {
            let mut num = i;
            let mut val: BigUint = BigUint::try_from(0).unwrap();
            let mut b: u32 = 0;
            let two:BigUint = BigUint::try_from(2).unwrap();
            while num!=0 {
                if num&1 == 1{
                    let p = b*d;
                    val += two.pow(p);
                }
                b+=1;
                num = num>>1;
            }
            precomp_array.push(mul_naive(C::ScalarField::from_noncanonical_biguint(val), C::GENERATOR_PROJECTIVE).to_affine());
        }
        for point in precomp_array{
            precomp_array_target.push(self.constant_affine_point(point))
        }
        precomp_array_target
    }

    fn fixed_base_curve_scalar_mul_comb<C:Curve>(&mut self, n: &Vec<BoolTarget>) -> AffinePointTarget<C> {
        let r = 4;
        let d = 64;
        let precomp = self.precompute_comb_array();
        let big_one = <C as Curve>::ScalarField::from_noncanonical_biguint(
            BigUint::from_str(
                "1",
            )
            .unwrap(),
        );
        let init = (CurveScalar(big_one) * C::GENERATOR_PROJECTIVE).to_affine();
        let init_target = self.constant_affine_point(init.clone());
        let mut result = self.add_virtual_affine_point_target();
        self.connect_affine_point(&init_target, &result);
        let col_0 = self.le_sum(n[0..(r*d)].iter().step_by(d).rev());

        let val_0 = self.random_access_curve_points(col_0, precomp.clone());

        result = self.curve_add(&result, &val_0);
        let to_add = self.constant_affine_point(-init);
        result = self.curve_add(&result, &to_add);
        let zero = self.zero();
        for i in (0..d-1).rev() {
            result = self.curve_double(&result);
            let col = self.le_sum(n[(d-1-i)..(r*d-i)].iter().step_by(d).rev());
            let val = self.random_access_curve_points(col, precomp.clone());
            // result = builder.curve_add(&result, &val);
            let is_zero = self.is_equal(col, zero);
            let should_add = self.not(is_zero);
            result = self.curve_conditional_add(&result, &val , should_add);
        }
        result
    }
}


// Generator logic well explained in: https://polymerlabs.medium.com/a-tutorial-on-writing-proofs-with-plonky2-part-ii-23f7a93ebabc
#[derive(Debug, Default)]
pub struct CurvePointDecompressionGenerator<F: RichField + Extendable<D>, const D: usize, C: Curve> {
    compressed: Vec<BoolTarget>,
    new_point: AffinePointTarget<C>,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> SimpleGenerator<F, D>
    for CurvePointDecompressionGenerator<F, D, C>
{
    fn dependencies(&self) -> Vec<Target> {
        self.compressed.iter().cloned().map(|item| item.target).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let bits = self.compressed.iter().map(|bt| witness.get_bool_target(bt.clone())).collect::<Vec<_>>();
        let mut bytes: [u8; 32] = [0; 32];
        for (byte_idx, chunk) in bits.chunks(8).enumerate() {
            let mut byte = 0u8;

            for (bit_idx, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - bit_idx);
                }
            }

            bytes[31 - byte_idx] = byte;
        }
        let decompressed_point = point_decompress(bytes.as_slice());

        out_buffer.set_biguint_target(&self.new_point.x.value, &decompressed_point.x.to_canonical_biguint());
        out_buffer.set_biguint_target(&self.new_point.y.value, &decompressed_point.y.to_canonical_biguint());
    }

    fn id(&self) -> String {
        "CurvePointDecompressionGenerator".to_string()
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>) -> plonky2::util::serialization::IoResult<()> {
        dst.write_target_bool_vec(&self.compressed)?;
        self.new_point.serialize(dst)
    }

    fn deserialize(src: &mut plonky2::util::serialization::Buffer, _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>) -> plonky2::util::serialization::IoResult<Self>
    where
        Self: Sized {
        let compressed_bool_target = src.read_target_bool_vec()?;
        let new_point = AffinePointTarget::deserialize(src)?;
        Ok(Self {
            compressed: compressed_bool_target,
            new_point: new_point,
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use anyhow::Result;
        use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::types::{Field, Sample};

    use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_base::Ed25519Base;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    #[test]
    fn test_curve_point_is_valid() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let g_target = builder.constant_affine_point(g);
        let neg_g_target = builder.curve_neg(&g_target);

        builder.curve_assert_valid(&g_target);
        builder.curve_assert_valid(&neg_g_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn test_curve_point_is_not_valid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let not_g = AffinePoint::<Ed25519> {
            x: g.x,
            y: g.y + Ed25519Base::ONE,
            zero: g.zero,
        };
        let not_g_target = builder.constant_affine_point(not_g);

        builder.curve_assert_valid(&not_g_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap()
    }

    #[test]
    fn test_curve_double() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let g_target = builder.constant_affine_point(g);
        let neg_g_target = builder.curve_neg(&g_target);

        let double_g = g.double();
        let double_g_expected = builder.constant_affine_point(double_g);
        builder.curve_assert_valid(&double_g_expected);

        let double_neg_g = (-g).double();
        let double_neg_g_expected = builder.constant_affine_point(double_neg_g);
        builder.curve_assert_valid(&double_neg_g_expected);

        let double_g_actual = builder.curve_double(&g_target);
        let double_neg_g_actual = builder.curve_double(&neg_g_target);
        builder.curve_assert_valid(&double_g_actual);
        builder.curve_assert_valid(&double_neg_g_actual);

        builder.connect_affine_point(&double_g_expected, &double_g_actual);
        builder.connect_affine_point(&double_neg_g_expected, &double_neg_g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    fn test_curve_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let double_g = g.double();
        let g_plus_2g = g + double_g;
        let g_plus_2g_expected = builder.constant_affine_point(g_plus_2g.to_affine());
        builder.curve_assert_valid(&g_plus_2g_expected);

        let g_target = builder.constant_affine_point(g);
        let double_g_target = builder.curve_double(&g_target);
        let g_plus_2g_actual = builder.curve_add(&g_target, &double_g_target);
        builder.curve_assert_valid(&g_plus_2g_actual);

        builder.connect_affine_point(&g_plus_2g_expected, &g_plus_2g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    fn test_curve_conditional_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let double_g = g.double();
        let g_plus_2g = g + double_g;
        let g_plus_2g_expected = builder.constant_affine_point(g_plus_2g.to_affine());

        let g_expected = builder.constant_affine_point(g);
        let double_g_target = builder.curve_double(&g_expected);
        let t = builder._true();
        let f = builder._false();
        let g_plus_2g_actual = builder.curve_conditional_add(&g_expected, &double_g_target, t);
        let g_actual = builder.curve_conditional_add(&g_expected, &double_g_target, f);

        builder.connect_affine_point(&g_plus_2g_expected, &g_plus_2g_actual);
        builder.connect_affine_point(&g_expected, &g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_curve_mul() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_PROJECTIVE.to_affine();
        let five = Ed25519Scalar::from_canonical_usize(5);
        let neg_five = five.neg();
        let neg_five_scalar = CurveScalar::<Ed25519>(neg_five);
        let neg_five_g = (neg_five_scalar * g.to_projective()).to_affine();
        let neg_five_g_expected = builder.constant_affine_point(neg_five_g);
        builder.curve_assert_valid(&neg_five_g_expected);

        let g_target = builder.constant_affine_point(g);
        let neg_five_target = builder.constant_nonnative(neg_five);
        let neg_five_g_actual = builder.curve_scalar_mul(&g_target, &neg_five_target);
        builder.curve_assert_valid(&neg_five_g_actual);

        builder.connect_affine_point(&neg_five_g_expected, &neg_five_g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_curve_random() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rando =
            (CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE).to_affine();
        assert!(rando.is_valid());
        let randot = builder.constant_affine_point(rando);

        let two_target = builder.constant_nonnative(Ed25519Scalar::TWO);
        let randot_doubled = builder.curve_double(&randot);
        let randot_times_two = builder.curve_scalar_mul(&randot, &two_target);
        builder.connect_affine_point(&randot_doubled, &randot_times_two);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }
}
