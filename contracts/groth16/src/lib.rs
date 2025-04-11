#![cfg_attr(not(test), no_std)]
use groth16::{verify_proof, Proof, VerifyingKey};
use soroban_sdk::{
    contract, contractimpl,
    crypto::bls12_381::{self, Fr, G1Affine},
    vec, Env, String, Vec,
};

// pub mod decompression;
pub mod errors;
// pub mod groth15;
pub mod groth16;

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
    pub fn verify(env: Env) -> bool {
        let bls = env.crypto().bls12_381();

        
        true
    }
}

mod groth16_test;
mod test;
