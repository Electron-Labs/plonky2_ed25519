#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::fs;
use std::marker::PhantomData;
use anyhow::Result;
use std::time::Instant;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, ProverOnlyCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ed25519::curve::eddsa::{
    SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_SIG1,
};
use plonky2_ed25519::gadgets::eddsa::{fill_circuits, make_verify_circuits, verify_using_preprocessed_sha_block};
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2_sha512::gadgets::sha512::array_to_bits;
use plonky2::plonk::prover::prove;
use serde::{Deserialize, Serialize};
use plonky2_ed25519::serialization::{Ed25519GateSerializer, Ed25519GeneratorSerializer};

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

#[derive(Serialize, Deserialize)]
struct Data {
    bytes: Vec<u8>
}

fn prove_ed25519_from_sha512_block<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    sha_preprocessed: &Vec<u8>,
    pub_key: &Vec<u8>,
    sig: &Vec<u8>
)
    where
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let sha_block_bits = array_to_bits(sha_preprocessed);
    let pub_key_bits = array_to_bits(pub_key);
    let sig_bits = array_to_bits(sig);

    let mut sha_block_target = Vec::<BoolTarget>::new();
    let mut pub_key_target = Vec::<BoolTarget>::new();
    let mut sig_target = Vec::<BoolTarget>::new();

    for i in 0..2048 {
        sha_block_target.push(builder.add_virtual_bool_target_unsafe());
    }
    for i in 0..256 {
        pub_key_target.push(builder.add_virtual_bool_target_unsafe());
    }
    for i in 0..512 {
        sig_target.push(builder.add_virtual_bool_target_unsafe());
    }
    verify_using_preprocessed_sha_block(&mut builder, &sha_block_target, &pub_key_target, &sig_target);
    println!("Starting to build the circuit with num gates {:?}", builder.num_gates());
    let data = builder.build::<C>();
    println!("Circuit built");

    let mut pw = PartialWitness::new();
    for i in 0..2048 {
        pw.set_bool_target(sha_block_target[i], sha_block_bits[i]);
    }
    for i in 0..512 {
        pw.set_bool_target(sig_target[i], sig_bits[i]);
    }
    for i in 0..256 {
        pw.set_bool_target(pub_key_target[i], pub_key_bits[i]);
    }
    println!("Starting proof gen..");
    let s1 = Instant::now();
    let proof = data.prove(pw).unwrap();
    println!("Time taken to generate the proof {:?}", s1.elapsed());
    data.verify(proof.clone()).expect("verify error");
}

fn dump_bytes_to_json(bytes: Vec<u8>, json_path: &str) {
    // Serialize Vec<u8> to json
    let serialized_data = serde_json::to_string(&Data { bytes: bytes.clone() })
        .expect("Failed to serialize data");
    // Write json to file
    fs::write(json_path, serialized_data).expect("Failed to write to file");
}

fn read_bytes_from_json(json_path: &str) -> Vec<u8> {
    // Read json data
    let json_data = fs::read_to_string(json_path).expect("Failed to read from file");
    // Deserialize json back to Vec<u8>
    let deserialized_data: Data = serde_json::from_str(&json_data).expect("Failed to deserialize data");
    deserialized_data.bytes
}

fn build_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    msg_len: usize,
    storage_dir: &str
)
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let _targets = make_verify_circuits(&mut builder, msg_len);
    println!("Building circuit with {:?} gates", builder.num_gates());
    let t = Instant::now();
    let data = builder.build::<C>();
    println!("Time taken to build the circuit : {:?}", t.elapsed());
    let cd_bytes = data.common.clone().to_bytes(&Ed25519GateSerializer).unwrap();
    dump_bytes_to_json(cd_bytes, format!("{storage_dir}/common_data.json").as_str());
    let prover_only_bytes = data.prover_only.to_bytes(&Ed25519GeneratorSerializer::<C, D> {_phantom: PhantomData::<C>}, &data.common).unwrap();
    dump_bytes_to_json(prover_only_bytes, format!("{storage_dir}/prover_only.json").as_str());
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    dump_bytes_to_json(verifier_only_bytes, format!("{storage_dir}/verifier_only.json").as_str());
}

fn generate_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    storage_dir: &str
)
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let cd_bytes = read_bytes_from_json(format!("{storage_dir}/common_data.json").as_str());
    let prover_only_bytes = read_bytes_from_json(format!("{storage_dir}/prover_only.json").as_str());
    let verifier_only_bytes = read_bytes_from_json(format!("{storage_dir}/verifier_only.json").as_str());

    let common_data = CommonCircuitData::<F, D>::from_bytes(cd_bytes, &Ed25519GateSerializer).unwrap();
    let prover_only = ProverOnlyCircuitData::<F, C, D>::from_bytes(
        prover_only_bytes.as_slice(),
        &Ed25519GeneratorSerializer::<C, D> {_phantom: PhantomData::<C>},
        &common_data
    ).unwrap();
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = make_verify_circuits(&mut builder, msg.len());
    println!("Starting proof generation");
    let mut pw = PartialWitness::new();
    fill_circuits::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    let t = Instant::now();
    let proof_with_pis = prove::<F, C, D>(&prover_only, &common_data, pw, &mut Default::default()).unwrap();
    println!("Time taken to generate proof {:?}", t.elapsed());

    let proof_with_pis_bytes = proof_with_pis.to_bytes();
    dump_bytes_to_json(proof_with_pis_bytes, format!("{storage_dir}/proof_with_pis.json").as_str());

    let data = CircuitData::<F, C, D> {
        prover_only,
        verifier_only,
        common: common_data,
    };
    data.verify(proof_with_pis).expect("verify error");
}


fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let msg = SAMPLE_MSG1.as_bytes();
    let sig = SAMPLE_SIG1.as_slice();
    let pk = SAMPLE_PK1.as_slice();
    build_circuit::<F, C, D>(msg.len(), ".");
    generate_proof::<F, C, D>(&msg, &sig, &pk, ".");
    Ok(())
}

fn main() -> Result<()> {
    // benchmark();
    let _ = benchmark();
    Ok(())
}

// [110, 8, 2, 17, 253, 252, 197,0,0,"9":0,"10":0,"11":0,"12":34,"13":72,"14":10,"15":32,"16":122,"17":142,"18":192,"19":235,"20":60,"21":200,"22":129,"23":138,"24":195,"25":28,"26":210,"27":246,"28":239,"29":120,"30":205,"31":133,"32":142,"33":55,"34":139,"35":49,"36":122,"37":88,"38":39,"39":159,"40":168,"41":141,"42":149,"43":188,"44":97,"45":173,"46":187,"47":96,"48":18,"49":36,"50":8,"51":2,"52":18,"53":32,"54":112,"55":168,"56":36,"57":7,"58":51,"59":201,"60":176,"61":92,"62":83,"63":27,"64":128,"65":6,"66":184,"67":203,"68":242,"69":148,"70":52,"71":222,"72":164,"73":187,"74":23,"75":226,"76":230,"77":212,"78":78,"79":193,"80":83,"81":74,"82":85,"83":83,"84":213,"85":154,"86":42,12,"88":8,"89":151,"90":206,"91":180,"92":172,"93":6,"94":16,"95":190,"96":144,"97":201,"98":199,"99":1,"100":50,"101":9,"102":111,"103":115,"104":109,"105":111,"106":115,"107":105,"108":115,"109":45,"110":49}
// msg [109, 8, 2, 17, 253, 252, 197, 0, 0, 0, 0, 0, 34, 72, 10, 32, 122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55, 139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96, 18, 36, 8, 2, 18, 32, 112, 168, 36, 7, 51, 201, 176, 92, 83, 27, 128, 6, 184, 203, 242, 148, 52, 222, 164, 187, 23, 226, 230, 212, 78, 193, 83, 74, 85, 83, 213, 154,                                                                                                                                                                                                                                                                                                                  42, 11, 8, 151, 206, 180, 172, 6, 16,                               211, 193, 250, 19, 50, 9, 111, 115, 109, 111, 115, 105, 115, 45, 49]
// sig [226, 162, 75, 243, 144, 204, 243, 68, 174, 40, 63, 58, 251, 123, 153, 105, 120, 238, 35, 63, 216, 100, 180, 171, 119, 149, 138, 252, 156, 7, 199, 108, 95, 59, 25, 183, 119, 161, 51, 46, 46, 147, 9, 31, 113, 191, 173, 81, 126, 238, 51, 91, 243, 227, 118, 46, 132, 191, 32, 218, 233, 51, 34, 6]
// pub key [232, 220, 244, 245, 129, 135, 207, 5, 177, 141, 204, 198, 208, 136, 74, 224, 139, 244, 169, 141, 136, 113, 125, 15, 255, 146, 162, 182, 244, 87, 77, 71]
// signed_msg [226, 162, 75, 243, 144, 204, 243, 68, 174, 40, 63, 58, 251, 123, 153, 105, 120, 238, 35, 63, 216, 100, 180, 171, 119, 149, 138, 252, 156, 7, 199, 108, 232, 220, 244, 245, 129, 135, 207, 5, 177, 141, 204, 198, 208, 136, 74, 224, 139, 244, 169, 141, 136, 113, 125, 15, 255, 146, 162, 182, 244, 87, 77, 71, 109, 8, 2, 17, 253, 252, 197, 0, 0, 0, 0, 0, 34, 72, 10, 32, 122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55, 139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96, 18, 36, 8, 2, 18, 32, 112, 168, 36, 7, 51, 201, 176, 92, 83, 27, 128, 6, 184, 203, 242, 148, 52, 222, 164, 187, 23, 226, 230, 212, 78, 193, 83, 74, 85, 83, 213, 154, 42, 11, 8, 151, 206, 180, 172, 6, 16, 211, 193, 250, 19, 50, 9, 111, 115, 109, 111, 115, 105, 115, 45, 49]


// [109, 8, 2, 17, 253, 252, 197, 0, 0, 0, 0, 0, 34, 72, 10, 32, 122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55, 139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96, 18, 36, 8, 2, 18, 32, 112, 168, 36, 7, 51, 201, 176, 92, 83, 27, 128, 6, 184, 203, 242, 148, 52, 222, 164, 187, 23, 226, 230, 212, 78, 193, 83, 74, 85, 83, 213, 154, 42, 11, 8, 151, 206, 180, 172, 6, 16, 211, 193, 250, 19, 50, 9, 111, 115, 109, 111, 115, 105, 115, 45, 49]
// [110, 8, 2, 17, 253, 252, 197, 0, 0, 0, 0, 0, 34, 72, 10, 32, 122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55, 139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96, 18, 36, 8, 2, 18, 32, 112, 168, 36, 7, 51, 201, 176, 92, 83, 27, 128, 6, 184, 203, 242, 148, 52, 222, 164, 187, 23, 226, 230, 212, 78, 193, 83, 74, 85, 83, 213, 154, 42, 12, 8, 151, 206, 180, 172, 6, 16, 190, 144, 201, 199, 1, 50, 9, 111, 115, 109, 111, 115, 105, 115, 45, 49]
// [109 8 2 17 253 252 197 0 0 0 0 0 34 72 10 32 122 142 192 235 60 200 129 138 195 28 210 246 239 120 205 133 142 55 139 49 122 88 39 159 168 141 149 188 97 173 187 96 18 36 8 2 18 32 112 168 36 7 51 201 176 92 83 27 128 6 184 203 242 148 52 222 164 187 23 226 230 212 78 193 83 74 85 83 213 154 42 11 8 151 206 180 172 6 16 211 193 250 19 50 9 111 115 109 111 115 105 115 45 49]