use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::Neg;
use soroban_sdk::{
    crypto::bls12_381::{Bls12_381, Fr, G1Affine, G2Affine},
    vec, Vec,
};

use ark_bls12_381::G1Affine as G1AffineArk;

pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>, // precomputed public inputs
}

pub fn verify_proof(
    bls: Bls12_381,
    vk: &VerifyingKey,
    proof: &Proof,
    public_inputs: Vec<Fr>, // field elements
) -> bool {
    // 1. Check input length
    if (public_inputs.len() + 1) != vk.gamma_abc_g1.len() {
        return false;
    }

    // 2. Compute acc = vk.gamma_abc_g1[0] + sum(input_i * vk.gamma_abc_g1[i])
    let mut acc: G1Affine = vk.gamma_abc_g1.get_unchecked(0u32);
    for (i, input) in public_inputs.iter().enumerate() {
        acc = bls.g1_add(
            &acc,
            &bls.g1_mul(&vk.gamma_abc_g1.get_unchecked(i as u32 + 1), &input),
        );
    }

    // TODO: to get negative of G1Affine, we use ark since we don't have negation in stellar bls12_381
    let mut neg_acc_bytes = [0u8; 96];
    G1AffineArk::deserialize_uncompressed(&acc.to_array()[..])
        .unwrap()
        .neg()
        .serialize_uncompressed(&mut neg_acc_bytes[..])
        .unwrap();

    let mut neg_alpha_g1_bytes = [0u8; 96];
    G1AffineArk::deserialize_uncompressed(&vk.alpha_g1.to_array()[..])
        .unwrap()
        .neg()
        .serialize_uncompressed(&mut neg_alpha_g1_bytes[..])
        .unwrap();

    let mut neg_c = [0u8; 96];
    G1AffineArk::deserialize_uncompressed(&proof.c.to_array()[..])
        .unwrap()
        .neg()
        .serialize_uncompressed(&mut neg_c[..])
        .unwrap();

    let neg_alpha_g1 = G1Affine::from_array(bls.env(), &neg_alpha_g1_bytes);
    let neg_acc = G1Affine::from_array(bls.env(), &neg_acc_bytes);
    let neg_proof_c = G1Affine::from_array(bls.env(), &neg_c);

    bls.pairing_check(
        vec![
            bls.env(),
            proof.a.clone(),
            neg_alpha_g1,
            neg_acc,
            neg_proof_c,
        ],
        vec![
            bls.env(),
            proof.b.clone(),
            vk.beta_g2.clone(),
            vk.gamma_g2.clone(),
            vk.delta_g2.clone(),
        ],
    )
}

// pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
//     let bigint = BigUint::from_bytes_be(bytes);
//     bigint < ark_bls12_381::Fr::MODULUS.into()
// }
