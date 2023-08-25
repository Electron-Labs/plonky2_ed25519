#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use std::time::Instant;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ed25519::curve::eddsa::{
    SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_SIG1, 
};
use plonky2_ed25519::gadgets::eddsa::{fill_circuits, make_verify_circuits};
use plonky2::field::extension::Extendable;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn prove_ed25519<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
) -> Result<ProofTuple<F, C, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());

    let targets = make_verify_circuits(&mut builder, msg.len());
    let mut pw = PartialWitness::new();
    fill_circuits::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    println!("Building ed25519 circuit with {:?} gates", builder.num_gates());
    let s0 = Instant::now();
    let data = builder.build::<C>();
    println!("Time taken to build the circuit : {:?}", s0.elapsed());
    let s1 = Instant::now();
    let proof = data.prove(pw).unwrap();
    println!("Time taken to generate the proof : {:?}", s1.elapsed());
    let s2 = Instant::now();
    data.verify(proof.clone()).expect("verify error");
    println!("Time taken to verify the proof : {:?}", s2.elapsed());
    Ok((proof, data.verifier_only, data.common))
}


fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    prove_ed25519::<F,C,D>(
        SAMPLE_MSG1.as_bytes(),
        SAMPLE_SIG1.as_slice(),
        SAMPLE_PK1.as_slice(),
    )
    .expect("prove error 1");
    Ok(())
}

fn main() -> Result<()> {
    // benchmark();
    let _ = benchmark();
    Ok(())
}
