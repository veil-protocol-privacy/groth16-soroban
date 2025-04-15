#![no_std]
pub mod errors;
pub mod groth16;

use errors::Groth16Error;
use groth16::{verify_proof, Proof, VerifyingKey};
use soroban_sdk::{contract, contractimpl, crypto::bls12_381::Fr, Bytes, BytesN, Env, Vec};

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
        let proof = Proof::try_from_bytes(proof)?;
        let vk = VerifyingKey::try_from_bytes(vk, public_inputs.len())?;
        let mut pi = Vec::new(&env);
        for i in public_inputs {
            let i = Fr::from_bytes(i);
            pi.push_back(i);
        }

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
