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
        if vk.len() != 672 + 96 * (public_inputs.len() + 1) {
            return Err(Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs);
        }

        let proof = &proof.to_array();

        let a = G1Affine::from_array(
            &env,
            &proof[0..96].try_into().expect("Slice must be 92 bytes"),
        );

        let b = G2Affine::from_array(
            &env,
            &proof[96..288].try_into().expect("Slice must be 192 bytes"),
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

        let mut ic: Vec<G1Affine> = vec![
            &env,
            G1Affine::from_array(
                &env,
                &vk.slice(672..768)
                    .try_into()
                    .expect("Slice must be 96 bytes"),
            ),
        ];
        let mut pi: Vec<Fr> = vec![&env];
        for i in 0..public_inputs.len() {
            let input = public_inputs.get_unchecked(i);
            pi.push_back(Fr::from_bytes(input));
            ic.push_back(G1Affine::from_array(
                &env,
                &vk.slice(672 + (i + 1) * 96..768 + (i + 1) * 96)
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
    }
}

#[cfg(test)]
pub mod groth16_test;
#[cfg(test)]
mod test;
