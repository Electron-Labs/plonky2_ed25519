use plonky2::field::types::{Field, PrimeField};
use crate::curve::curve_types::{AffinePoint, Curve, ProjectivePoint};
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize, Default)]
pub struct Ed25519;

impl Curve for Ed25519 {
    type BaseField = Ed25519Base;
    type ScalarField = Ed25519Scalar;
    const A: Self::BaseField = Ed25519Base::NEG_ONE;
    const D: Self::BaseField = Ed25519Base([
        0x75eb4dca135978a3,
        0x00700a4d4141d8ab,
        0x8cc740797779e898,
        0x52036cee2b6ffe73,
    ]);
    const GENERATOR_AFFINE: AffinePoint<Self> = AffinePoint {
        x: ED25519_GENERATOR_X,
        y: ED25519_GENERATOR_Y,
        zero: false
    };
}

pub const ED25519_ZERO: AffinePoint<Ed25519> = AffinePoint::ZERO;

/// 15112221349535400772501151409588531511454012693041857206046113283949847762202
const ED25519_GENERATOR_X: Ed25519Base = Ed25519Base([
    0xc9562d608f25d51a,
    0x692cc7609525a7b2,
    0xc0a4e231fdd6dc5c,
    0x216936d3cd6e53fe,
]);

/// 46316835694926478169428394003475163141307993866256225615783033603165251855960
const ED25519_GENERATOR_Y: Ed25519Base = Ed25519Base([
    0x6666666666666658,
    0x6666666666666666,
    0x6666666666666666,
    0x6666666666666666,
]);

/// A simple, somewhat inefficient implementation of multiplication which is used as a reference
/// for correctness.
/// src = https://github.com/mir-protocol/plonky2-ecdsa/blob/main/src/curve/secp256k1.rs#L84
pub(crate) fn mul_naive<C: Curve>(
    lhs: C::ScalarField,
    rhs: ProjectivePoint<C>
) -> ProjectivePoint<C> {
    let mut g = rhs;
    let mut sum= ProjectivePoint::ZERO;
    for limb in lhs.to_canonical_biguint().to_u64_digits().iter() {
        for j in 0..64 {
            if (limb >> j & 1u64) != 0u64{
                sum = sum + g;
            }
            g = g.double();
        }
    }
    assert!(sum.to_affine().is_valid());
    assert!(sum.is_valid());
    sum
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use num::BigUint;
    use plonky2::field::types::Field;
    use plonky2_sha512::gadgets::sha512::array_to_bits;
    use crate::curve::curve_types::{AffinePoint, Curve, ProjectivePoint};
    use crate::curve::ed25519::{Ed25519, mul_naive};
    use crate::field::ed25519_scalar::Ed25519Scalar;

    #[test]
    fn test_generator() {
        let g  = Ed25519::GENERATOR_AFFINE;
        assert!(g.is_valid());
        assert!(g.to_projective().is_valid());

        let neg_g = AffinePoint::<Ed25519> {
            x: -g.x,
            y: g.y,
            zero: g.zero
        };

        assert!(neg_g.is_valid());
        assert!(neg_g.to_projective().is_valid());
    }

    #[test]
    fn test_naive_multiplication() {
        let g = Ed25519::GENERATOR_PROJECTIVE;
        let ten = Ed25519Scalar::from_noncanonical_biguint(BigUint::try_from(10).unwrap());
        let product = mul_naive(ten, g);
        let sum = g + g + g + g + g + g + g + g + g + g;
        assert_eq!(product, sum);
    }

    #[test]
    fn test_doubling() {
        let g = Ed25519::GENERATOR_AFFINE;
        let double = g.double().double();
        let sum = g + g + g + g;
        let mul = mul_naive(Ed25519Scalar::from_noncanonical_biguint(BigUint::try_from(4).unwrap()), g.to_projective());
        println!("double: {:?}", double);
        println!("sum: {:?}", sum.to_affine());
        println!("mul: {:?}", mul.to_affine());
        assert_eq!(double, sum.to_affine());
    }

    #[test]
    fn test_g1_multiplication() {
        let lhs = Ed25519Scalar::from_noncanonical_biguint(BigUint::from_slice(&[
            1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888,
        ]));
        assert_eq!(
            Ed25519::convert(lhs) * Ed25519::GENERATOR_PROJECTIVE,
            mul_naive(lhs, Ed25519::GENERATOR_PROJECTIVE)
        );
    }

    #[test]
    fn make_comp_precomp() {
        let g = Ed25519::GENERATOR_AFFINE;
        let d: u32 = 32;
        let mut precomp_arr: Vec<ProjectivePoint<Ed25519>> = vec![];
        for i in 1..256 {
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
            precomp_arr.push(mul_naive(Ed25519Scalar::from_noncanonical_biguint(val), g.to_projective()));
        }
        println!("{:?}", precomp_arr[0]);
        println!("{:?}", g);
    }

    fn bool_vec_to_usize(v: Vec<bool>) -> usize {
        let mut result = 0;
    
        for (index, &value) in v.iter().rev().enumerate() {
            if value {
                result |= 1 << index;
            }
        }
    
        result
    }

    #[test]
    fn test_bool_vec_to_usize() {
        let x = bool_vec_to_usize(vec![false,true]);
        println!("x -> {:?}", x);
    }

    #[test]
    fn do_comb_mult() {
        let s: Vec<bool> = vec![false, false, true, true, false, false, false, false, true, true, true, false, true, true, true, true, false, false, false, true, true, false, true, true, true, true, true, true, true, true, true, false, true, true, true, false, true, true, false, true, false, false, false, false, true, true, false, true, false, false, true, false, true, true, true, false, true, true, true, true, true, true, true, false, true, true, true, false, false, false, false, true, true, true, false, true, true, false, false, true, true, true, true, false, true, true, true, false, true, true, true, true, true, false, true, true, true, true, true, false, false, true, true, true, false, true, true, false, false, false, true, true, false, true, false, true, true, false, true, false, true, false, false, false, false, true, true, false, false, false, true, true, true, false, false, true, false, false, true, true, false, false, false, false, true, false, true, true, false, false, false, false, true, true, true, false, true, false, true, false, true, false, false, true, true, false, true, true, true, true, false, true, false, true, true, true, false, false, true, true, true, false, true, false, true, true, true, true, false, true, false, true, true, false, false, true, true, true, true, false, true, true, true, true, true, false, true, false, true, true, false, false, false, true, false, false, true, false, true, true, false, true, false, true, false, false, true, true, false, false, false, false, false, true, true, true, false, true, false, false, true, true, false, true, false, true, true, true, true, true, false, false, true, true, true, false];
        let s_biguint = BigUint::from_str("22133486400421073832505818076869675288519981561332828799409059411505490221006").unwrap();
        println!("{:?}",s_biguint.to_bytes_le());
        println!("{:?}",array_to_bits(&[1]));
        let r = 4;
        let d: u32 = 64;
        let mut precomp_array: Vec<AffinePoint<Ed25519>> = vec![Ed25519::GENERATOR_AFFINE]; // pushing generator only at 0 for now
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
            precomp_array.push(mul_naive(Ed25519Scalar::from_noncanonical_biguint(val), Ed25519::GENERATOR_PROJECTIVE).to_affine());
        }
        let mut col_0: Vec<bool> = vec![];
        for j in 0..r{
            let x = s[(j*d) as usize];
            col_0.push(x);
        }
        let ss_0: usize = bool_vec_to_usize(col_0);
        if ss_0 == 0{
            println!("There was a fuckin zero");
        }
        let val1_0 = precomp_array.get(ss_0).unwrap();
        println!("val1_0 {:?}", ss_0);
        let mut ans = val1_0.clone();
        for i in (0..d-1).rev(){
            ans = ans.double(); // subtract 2 * gen_affine at the end??
            let mut col: Vec<bool> = vec![];
            for j in 0..r{
                // s.as_slice()[(j*d)..(j*d+d)].reverse()[i]
                // let x = s[((j*d) as usize..(j*d+d) as usize)][(d-1-i) as usize];
                let x = s[((j+1)*d-i-1) as usize];
                // convert to u8 which will be the index to select
                col.push(x);
            }
            // println!("index {:?}", col);
            let ss: usize = bool_vec_to_usize(col);
            if ss == 0{
                println!("There was a fuckin zero");
            }
            let val1 = precomp_array.get(ss).unwrap();
            // println!("val::{:?}", val);
            ans = (ans.to_projective() + val1.to_projective()).to_affine();
            //ans = (ans.to_projective() + Ed25519::GENERATOR_AFFINE.double().neg().to_projective()).to_affine();
        }
        // ans = (ans.to_projective() + Ed25519::GENERATOR_PROJECTIVE.neg()).to_affine();
        // ans = (ans.to_projective() + Ed25519::GENERATOR_PROJECTIVE.neg()).to_affine();
        println!("{:?}", ans);
        println!("{:?}", mul_naive(Ed25519Scalar::from_noncanonical_biguint(s_biguint), Ed25519::GENERATOR_PROJECTIVE).to_affine())
    }

}