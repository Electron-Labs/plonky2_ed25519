use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::extension::Extendable;
use plonky2_crypto::biguint::BigUintTarget;
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_sha512::gadgets::sha512::{array_to_bits, make_sha512_circuit};
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::gadgets::curve::CircuitBuilderCurve;
use crate::gadgets::nonnative::CircuitBuilderNonNative;

pub struct EDDSATargets {
    pub msg: Vec<BoolTarget>,
    pub sig: Vec<BoolTarget>,
    pub pk: Vec<BoolTarget>,
}

fn bits_in_le(input_vec: Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut result = Vec::with_capacity(input_vec.len());
    
    input_vec
        .chunks_exact(8)
        .for_each(|chunk| result.extend(chunk.iter().rev()));

    result.reverse();
    result
}

pub fn biguint_to_bits_target<F: RichField + Extendable<D>, const D: usize, const B: usize>(
    builder: &mut CircuitBuilder<F, D>,
    num: &BigUintTarget,
) -> Vec<BoolTarget> {
    let mut bool_vec = Vec::new();
    
    let limb_indices: Vec<usize> = (0..num.num_limbs()).collect();
    for i in limb_indices.into_iter().rev() {
        let bits_in_limb = builder.split_le_base::<B>(num.get_limb(i).0, 32);
        bool_vec.extend(bits_in_limb.into_iter().rev().map(|bit| BoolTarget::new_unsafe(bit)));
    }

    bool_vec
}

pub fn bits_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> BigUintTarget {
    let bit_len = bits_target.len();
    assert_eq!(bit_len % 32, 0);

    let mut limb_targets = Vec::new();
    for chunk in bits_target.chunks(32).rev() {
        let summed_chunk = builder.le_sum(chunk.iter().clone().rev());
        limb_targets.push(U32Target(summed_chunk));
    }
    
    BigUintTarget { limbs: limb_targets }
}

fn connect_bool_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    src: &[BoolTarget],
    dest: &[BoolTarget]
) {
    assert_eq!(src.len(), dest.len());
    for (src_bit, dest_bit) in src.iter().zip(dest) {
        builder.connect(src_bit.target, dest_bit.target);
    }
}

pub fn make_verify_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: usize,
) -> EDDSATargets {
    let bits_in_message = msg_len * 8;
    let sha512_bit_length = bits_in_message + 512;
    let sha512_instance = make_sha512_circuit(builder, sha512_bit_length as u128);

    let mut msg = Vec::new();
    let mut sig = Vec::new();
    let mut pub_key = Vec::new();

    for idx in 0..bits_in_message{
        builder.register_public_input(sha512_instance.message[512+idx].target);
        msg.push(sha512_instance.message[512+idx]);
    }

    sig.resize_with(512,|| builder.add_virtual_bool_target_unsafe());

    pub_key.resize_with(256, || {
        let t = builder.add_virtual_bool_target_unsafe();
        builder.register_public_input(t.target);
        t
    });

    connect_bool_targets(builder, &sha512_instance.message[0..256], &sig[0..256]);
    connect_bool_targets(builder, &sha512_instance.message[256..512], &pub_key);

    let digest_bits_le = bits_in_le(sha512_instance.digest.clone());
    let digest_biguint = bits_to_biguint_target(builder, digest_bits_le);
    let h_scalar = builder.reduce::<Ed25519Scalar>(&digest_biguint);
    let s_sig_bits_le = bits_in_le(sig[256..512].to_vec());
    let pk_bits_le = bits_in_le(pub_key.clone());
    let point_a = builder.point_decompress::<Ed25519>(&pk_bits_le);
    let point_ha = builder.curve_scalar_mul_windowed(&point_a, &h_scalar);
    let r_bits_le = bits_in_le(sig[..256].to_vec());
    let point_r = builder.point_decompress(&r_bits_le);
    let point_sb = builder.fixed_base_curve_scalar_mul_comb(&s_sig_bits_le);
    let rhs = builder.curve_add(&point_r, &point_ha);

    builder.connect_affine_point(&point_sb, &rhs);

    return EDDSATargets { msg, sig, pk: pub_key };
}

pub fn fill_circuits<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    msg: &[u8],
    sig: &[u8],
    pk: &[u8],
    targets: &EDDSATargets,
) {
    assert_eq!(sig.len(), 64);
    assert_eq!(pk.len(), 32);

    let EDDSATargets {
        msg: msg_targets,
        sig: sig_targets,
        pk: pk_targets,
    } = targets;
    assert_eq!(msg.len() * 8, msg_targets.len());

    let sig_bits = array_to_bits(sig);
    let pk_bits = array_to_bits(pk);
    let msg_bits = array_to_bits(msg);

    for i in 0..msg_bits.len() {
        pw.set_bool_target(msg_targets[i], msg_bits[i]);
    }
    for i in 0..512 {
        pw.set_bool_target(sig_targets[i], sig_bits[i]);
    }
    for i in 0..256 {
        pw.set_bool_target(pk_targets[i], pk_bits[i]);
    }
}