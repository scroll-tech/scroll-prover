use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
};

use halo2_proofs::{
    arithmetic::BaseExt,
    pairing::bn256::{Fr, G1Affine},
    plonk::VerifyingKey,
    poly::commitment::Params,
};
use num_bigint::BigUint;
use pairing::bn256::Fq;

pub fn serialize_fr(f: &Fr) -> Vec<u8> {
    let mut buf = vec![];
    f.write(&mut buf).unwrap();
    buf
}

pub fn deserialize_fr(buf: Vec<u8>) -> Fr {
    Fr::read(&mut std::io::Cursor::new(buf)).unwrap()
}
pub fn serialize_fr_vec(v: &[Fr]) -> Vec<Vec<u8>> {
    v.iter().map(serialize_fr).collect()
}
pub fn deserialize_fr_vec(l2_buf: Vec<Vec<u8>>) -> Vec<Fr> {
    l2_buf.into_iter().map(deserialize_fr).collect()
}

pub fn serialize_fr_matrix(m: &[Vec<Fr>]) -> Vec<Vec<Vec<u8>>> {
    m.iter().map(|v| serialize_fr_vec(v.as_slice())).collect()
}

pub fn deserialize_fr_matrix(l3_buf: Vec<Vec<Vec<u8>>>) -> Vec<Vec<Fr>> {
    l3_buf.into_iter().map(deserialize_fr_vec).collect()
}

pub fn serialize_fr_tensor(t: &[Vec<Vec<Fr>>]) -> Vec<Vec<Vec<Vec<u8>>>> {
    t.iter()
        .map(|m| serialize_fr_matrix(m.as_slice()))
        .collect()
}

pub fn deserialize_fr_tensor(l4_buf: Vec<Vec<Vec<Vec<u8>>>>) -> Vec<Vec<Vec<Fr>>> {
    l4_buf.into_iter().map(deserialize_fr_matrix).collect()
}

pub fn serialize_instance(instance: &[Vec<Fr>]) -> Vec<u8> {
    let instances_for_serde = serialize_fr_matrix(instance);

    serde_json::to_vec(&instances_for_serde).unwrap()
}

pub fn load_instance(buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
    let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(buf).unwrap();
    deserialize_fr_tensor(instances)
}

pub fn read_all(filename: &str) -> Vec<u8> {
    let mut buf = vec![];
    let mut fd = std::fs::File::open(filename).unwrap();
    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn write_file(folder: &mut PathBuf, filename: &str, buf: &[u8]) {
    folder.push(filename);
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(buf).unwrap();
}

pub fn load_target_circuit_params(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "sample_circuit.params")
}

pub fn load_target_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "sample_circuit.vkey")
}

pub fn load_target_circuit_instance(folder: &mut PathBuf, index: usize) -> Vec<u8> {
    read_file(folder, &format!("sample_circuit_instance{}.data", index))
}

pub fn load_target_circuit_proof(folder: &mut PathBuf, index: usize) -> Vec<u8> {
    read_file(folder, &format!("sample_circuit_proof{}.data", index))
}

pub fn load_verify_circuit_params(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.params")
}

pub fn load_verify_circuit_vk(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit.vkey")
}

pub fn load_verify_circuit_instance(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_instance.data")
}

pub fn load_verify_circuit_proof(folder: &mut PathBuf) -> Vec<u8> {
    read_file(folder, "verify_circuit_proof.data")
}

pub fn write_verify_circuit_params(folder: &mut PathBuf, verify_circuit_params: &Params<G1Affine>) {
    folder.push("verify_circuit.params");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    verify_circuit_params.write(&mut fd).unwrap();
}

pub fn serialize_vk(vk: &VerifyingKey<G1Affine>) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    vk.write(&mut result).unwrap();
    result
}

pub fn write_verify_circuit_vk(folder: &mut PathBuf, verify_circuit_vk: &[u8]) {
    folder.push("verify_circuit.vkey");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    fd.write_all(verify_circuit_vk).unwrap()
}

pub fn field_to_bn(f: &Fq) -> BigUint {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

pub fn serialize_commitments(buf: &[Vec<G1Affine>]) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let mut fd = Cursor::new(&mut result);
    for v in buf {
        for commitment in v {
            let x = field_to_bn(&commitment.x);
            let y = field_to_bn(&commitment.y);
            let be = x
                .to_bytes_be()
                .into_iter()
                .chain(y.to_bytes_be().into_iter())
                .collect::<Vec<_>>();
            fd.write_all(&be).unwrap()
        }
    }
    result
}

pub fn write_verify_circuit_instance_commitments_be(folder: &mut PathBuf, buf: &[u8]) {
    folder.push("verify_circuit_instance_commitments_be.data");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    fd.write_all(buf).unwrap()
}

pub fn write_verify_circuit_instance(folder: &mut PathBuf, buf: &[u8]) {
    write_file(folder, "verify_circuit_instance.data", buf)
}

pub fn write_verify_circuit_proof(folder: &mut PathBuf, buf: &[u8]) {
    write_file(folder, "verify_circuit_proof.data", buf)
}

pub fn write_verify_circuit_proof_be(folder: &mut PathBuf, buf: &[u8]) {
    write_file(folder, "verify_circuit_proof_be.data", buf)
}

pub fn write_verify_circuit_solidity(folder: &mut PathBuf, buf: &[u8]) {
    write_file(folder, "verifier.sol", buf)
}

pub fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
    let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(buf).unwrap();
    instances
        .into_iter()
        .map(|l1| {
            l1.into_iter()
                .map(|l2| {
                    l2.into_iter()
                        .map(|buf| Fr::read(&mut std::io::Cursor::new(buf)).unwrap())
                        .collect()
                })
                .collect()
        })
        .collect()
}
