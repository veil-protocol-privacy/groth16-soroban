use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    IncompatibleVerifyingKeyWithNrPublicInputs = 1,
    ProofVerificationFailed = 2,
    PreparingInputsG1AdditionFailed = 3,
    PreparingInputsG1MulFailed = 4,
    InvalidG1Length = 5,
    InvalidG2Length = 6,
    InvalidPublicInputsLength = 7,
    DecompressingG1Failed = 8,
    DecompressingG2Failed = 9,
    PublicInputGreaterThenFieldSize = 10,
}
