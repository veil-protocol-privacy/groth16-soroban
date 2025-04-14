// #![cfg_attr(not(test), no_std)]
#![no_std]
pub mod errors;
pub mod groth16;

use errors::Groth16Error;
use groth16::{verify_proof, Proof, VerifyingKey};
use soroban_sdk::{
    contract, contractimpl,
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    vec, Bytes, BytesN, Env, Vec,
};

#[contract]
pub struct Groth16Contract;

// This is a sample contract. Replace this placeholder with your own contract logic.
// A corresponding test example is available in `test.rs`.
//
// For comprehensive examples, visit <https://github.com/stellar/soroban-examples>.
// The repository includes use cases for the Stellar ecosystem, such as data storage on
// the blockchain, token swaps, liquidity pools, and more.
//
// Refer to the official documentation:
// <https://developers.stellar.org/docs/build/smart-contracts/overview>.
#[contractimpl]
impl Groth16Contract {
    pub fn verify(
        env: Env,
        proof: BytesN<384>,
        vk: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<(), Groth16Error> {
        // Check vk length: must be equal to 672 + 96 * n
        // where n is the number of public inputs
        if vk.len() != 672 + 96 * public_inputs.len() {
            return Err(Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs);
        }

        let proof = &proof.to_array();

        let a = G1Affine::from_array(
            &env,
            &proof[0..92].try_into().expect("Slice must be 96 bytes"),
        );
        let b = G2Affine::from_array(
            &env,
            &proof[92..288].try_into().expect("Slice must be 192 bytes"),
        );
        let c = G1Affine::from_array(
            &env,
            &proof[288..384].try_into().expect("Slice must be 96 bytes"),
        );

        let proof = Proof { a, b, c };

        let alpha = G1Affine::from_array(
            &env,
            &vk.slice(0..96).try_into().expect("Slice must be 96 bytes"),
        );
        let beta = G2Affine::from_array(
            &env,
            &vk.slice(96..288)
                .try_into()
                .expect("Slice must be 192 bytes"),
        );
        let gamma = G2Affine::from_array(
            &env,
            &vk.slice(288..480)
                .try_into()
                .expect("Slice must be 192 bytes"),
        );
        let delta = G2Affine::from_array(
            &env,
            &vk.slice(480..672)
                .try_into()
                .expect("Slice must be 192 bytes"),
        );

        let mut ic: Vec<G1Affine> = vec![&env];
        let mut pi: Vec<Fr> = vec![&env];
        for i in 0..public_inputs.len() {
            let input = public_inputs.get_unchecked(i);
            pi.push_back(Fr::from_bytes(input));
            ic.push_back(G1Affine::from_array(
                &env,
                &vk.slice(672 + i * 96..768 + i * 96)
                    .try_into()
                    .expect("Slice must be 96 bytes"),
            ));
        }

        let vk = VerifyingKey {
            alpha_g1: alpha,
            beta_g2: beta,
            gamma_g2: gamma,
            delta_g2: delta,
            gamma_abc_g1: ic,
        };

        let bls = env.crypto().bls12_381();

        if !verify_proof(bls, &vk, &proof, pi) {
            return Err(Groth16Error::ProofVerificationFailed);
        }

        Ok(())

        // let a = G1Affine::from_array(
        //     &env,
        //     &PROOF[0..96].try_into().expect("Slice must be 96 bytes"),
        // );

        // let b = G2Affine::from_array(
        //     &env,
        //     &PROOF[96..288]
        //         .try_into()
        //         .expect("Slice must be `192` bytes"),
        // );
        // let c = G1Affine::from_array(
        //     &env,
        //     &PROOF[288..384].try_into().expect("Slice must be 96 bytes"),
        // );

        // let proof = Proof { a, b, c };

        // let alpha_g1 =
        //     G1Affine::from_array(&env, &VK[0..96].try_into().expect("Slice must be 96 bytes"));
        // let beta_g2 = G2Affine::from_array(
        //     &env,
        //     &VK[96..288].try_into().expect("Slice must be 192 bytes"),
        // );
        // let gamma_g2 = G2Affine::from_array(
        //     &env,
        //     &VK[288..480].try_into().expect("Slice must be 192 bytes"),
        // );
        // let delta_g2 = G2Affine::from_array(
        //     &env,
        //     &VK[480..672].try_into().expect("Slice must be 192 bytes"),
        // );

        // let ic: Vec<G1Affine> = vec![
        //     &env,
        //     G1Affine::from_array(&env, &P1),
        //     G1Affine::from_array(&env, &P2),
        // ];

        // let vk = VerifyingKey {
        //     alpha_g1,
        //     beta_g2,
        //     gamma_g2,
        //     delta_g2,
        //     gamma_abc_g1: ic,
        // };

        // let res = verify_proof(
        //     env.crypto().bls12_381(),
        //     &vk,
        //     &proof,
        //     vec![
        //         &env,
        //         Fr::from_bytes(BytesN::from_array(
        //             &env,
        //             &[
        //                 43, 208, 68, 170, 244, 217, 233, 104, 169, 196, 104, 2, 228, 225, 211, 30, 195,
        //                 13, 143, 171, 67, 82, 183, 9, 208, 189, 42, 151, 250, 111, 78, 199,
        //             ],
        //         )),
        //     ],
        // );

        // assert_eq!(res, true);
    }
}

#[cfg(test)]
pub mod groth16_test;
#[cfg(test)]
mod test;
