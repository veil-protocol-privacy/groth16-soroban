use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

    // 3. Compute neg_a = -proof.a
    // TODO: use ark as a workaround until the native implementation is available
    let mut neg_a = [0u8; 96];
    (-G1AffineArk::deserialize_uncompressed(&proof.a.to_array()[..]).unwrap())
        .serialize_uncompressed(&mut neg_a[..])
        .unwrap();

    let neg_a = G1Affine::from_array(bls.env(), &neg_a);

    // 4. Pairing check e(-proof.a, proof.b) * e(vk.alpha_g1, vk.beta_g2, vk.gamma_g2) * e(vk.gamma_g2, acc) * e(proof.c, vk.delta_g2) == 1
    let a = bls.pairing_check(
        vec![bls.env(), neg_a, vk.alpha_g1.clone(), acc, proof.c.clone()],
        vec![
            bls.env(),
            proof.b.clone(),
            vk.beta_g2.clone(),
            vk.gamma_g2.clone(),
            vk.delta_g2.clone(),
        ],
    );

    #[cfg(test)]
    {
        extern crate std;
        std::println!("pairing_check: {:?}", a);
    }
    return a;
}

// pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
//     let bigint = BigUint::from_bytes_be(bytes);
//     bigint < ark_bls12_381::Fr::MODULUS.into()
// }
