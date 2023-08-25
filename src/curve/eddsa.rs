use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use plonky2_sha512::gadgets::sha512::array_to_bits;
use sha2::{Sha512, Digest};
use num::{BigUint, Integer};
use plonky2::field::types::Field;
use crate::curve::curve_types::{AffinePoint, Curve};
use crate::curve::ed25519::{Ed25519, mul_naive, ED25519_ZERO};
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;



pub const SAMPLE_MSG1: &str = "test message";
pub const SAMPLE_MSG2: &str = "plonky2";
pub const SAMPLE_PK1: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];
pub const SAMPLE_SIG1: [u8; 64] = [
    104, 196, 204, 44, 176, 120, 225, 128, 47, 67, 245, 210, 247, 65, 201, 66, 34, 159, 217, 32,
    175, 224, 14, 12, 31, 231, 83, 160, 214, 122, 250, 68, 250, 203, 33, 143, 184, 13, 247, 140,
    185, 25, 122, 25, 253, 195, 83, 102, 240, 255, 30, 21, 108, 249, 77, 184, 36, 72, 9, 198, 49,
    12, 68, 8,
];
pub const SAMPLE_SIG2: [u8; 64] = [
    130, 82, 60, 170, 184, 218, 199, 182, 66, 19, 182, 14, 141, 214, 229, 180, 43, 19, 227, 183,
    130, 204, 69, 112, 171, 113, 6, 111, 218, 227, 249, 85, 57, 216, 145, 63, 71, 192, 201, 10, 54,
    234, 203, 8, 63, 240, 226, 101, 84, 167, 36, 246, 153, 35, 31, 52, 244, 82, 239, 137, 18, 62,
    134, 7,
];


pub fn point_decompress(s: &[u8]) -> AffinePoint<Ed25519> {
    if s.len() != 32 {
        panic!("Invalid length of byte array");
    }

    // Attempt to decompress the point.
    let compressed_y = CompressedEdwardsY::from_slice(s).unwrap();
    let option_point: Option<EdwardsPoint> = compressed_y.decompress();

    match option_point {
        Some(edwards_point) => {
            // Convert EdwardsPoint to your AffinePoint<Ed25519> type here.
            let x_biguint = BigUint::from_bytes_le(&edwards_point.get_x().as_bytes());
            let y_biguint = BigUint::from_bytes_le(&edwards_point.get_y().as_bytes());
            let affine_point = AffinePoint::nonzero(
                Ed25519Base::from_noncanonical_biguint(x_biguint),
                Ed25519Base::from_noncanonical_biguint(y_biguint)
            );
            affine_point
        },
        None => panic!("Failed to decompress point"),
    }
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

pub fn do_comb_mult(s: Vec<bool>) -> AffinePoint<Ed25519>{
    // let s: Vec<bool> = vec![false, false, true, true, false, false, false, false, true, true, true, false, true, true, true, true, false, false, false, true, true, false, true, true, true, true, true, true, true, true, true, false, true, true, true, false, true, true, false, true, false, false, false, false, true, true, false, true, false, false, true, false, true, true, true, false, true, true, true, true, true, true, true, false, true, true, true, false, false, false, false, true, true, true, false, true, true, false, false, true, true, true, true, false, true, true, true, false, true, true, true, true, true, false, true, true, true, true, true, false, false, true, true, true, false, true, true, false, false, false, true, true, false, true, false, true, true, false, true, false, true, false, false, false, false, true, true, false, false, false, true, true, true, false, false, true, false, false, true, true, false, false, false, false, true, false, true, true, false, false, false, false, true, true, true, false, true, false, true, false, true, false, false, true, true, false, true, true, true, true, false, true, false, true, true, true, false, false, true, true, true, false, true, false, true, true, true, true, false, true, false, true, true, false, false, true, true, true, true, false, true, true, true, true, true, false, true, false, true, true, false, false, false, true, false, false, true, false, true, true, false, true, false, true, false, false, true, true, false, false, false, false, false, true, true, true, false, true, false, false, true, true, false, true, false, true, true, true, true, true, false, false, true, true, true, false];
    // let s_biguint = BigUint::from_str("22133486400421073832505818076869675288519981561332828799409059411505490221006").unwrap();
    // println!("{:?}",s_biguint.to_bytes_le());
    // println!("{:?}",array_to_bits(&[1]));
    // return;
    // println!("biguint {:?}", s_biguint);
    let r = 4;
    let d: u32 = 64;
    let mut precomp_array: Vec<AffinePoint<Ed25519>> = vec![ED25519_ZERO]; // pushing generator only at 0 for now
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
    ans
    // ans = (ans.to_projective() + Ed25519::GENERATOR_PROJECTIVE.neg()).to_affine();
    // ans = (ans.to_projective() + Ed25519::GENERATOR_PROJECTIVE.neg()).to_affine();
    // println!("{:?}", ans);
    // println!("{:?}", mul_naive(Ed25519Scalar::from_noncanonical_biguint(s_biguint), Ed25519::GENERATOR_PROJECTIVE).to_affine())
}


pub fn bits_in_le(input_vec: Vec<bool>) -> Vec<bool> {
    let mut bits = Vec::new();
    for i in 0..input_vec.len() / 8 {
        for j in 0..8 {
            bits.push(input_vec[i * 8 + 7 - j]);
        }
    }
    bits.reverse();
    bits
}

pub fn verify_message_ed25519() -> anyhow::Result<()> {
    let msg = SAMPLE_MSG1.as_bytes();
    let sig= &SAMPLE_SIG1;
    let pk = &SAMPLE_PK1;
    let mut hash_input: Vec<u8> = Vec::new();
    hash_input.extend_from_slice(&sig[0..32]);
    hash_input.extend_from_slice(pk);
    hash_input.extend_from_slice(msg);
    let mut hasher = Sha512::new();
    hasher.update(hash_input.as_slice());
    let sha512_hash = hasher.finalize();
    let sha512_hash_ = BigUint::from_bytes_le(sha512_hash.as_slice());
    let sha512_hash_mod = sha512_hash_.mod_floor(&Ed25519Scalar::order());

    // Get affine point from
    // remove Dalek dependency
    let h = Ed25519Scalar::from_noncanonical_biguint(sha512_hash_mod);
    let pk = point_decompress(pk);
    assert!(pk.is_valid());
    let r = point_decompress(&sig[..32]);
    // let s = Ed25519Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&sig[32..]));
    // let mut x: Vec<u8> = vec![];
    // for bit in &sig[32..]{
    //     x.insert(0, bit.clone());
    // }
    // println!("x::{:?}", x);
    // let s = array_to_bits(&x);
    let s_ = bits_in_le(array_to_bits(&sig[32..]));

    let sb = do_comb_mult(s_);// lhs
    let ha = mul_naive(h, pk.to_projective());
    let rhs = r + ha.to_affine();
    println!("rhs -> {:?}", rhs.to_affine());
    println!("lhs -> {:?}", sb);

    assert!(sb == rhs.to_affine());
    Ok(())
}


// mod tests {
//     use super::verify_message_ed25519;

//     #[test]
//     fn test_ed25519() {
//         verify_message_ed25519();
//     }
// }