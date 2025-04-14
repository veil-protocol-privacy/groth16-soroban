#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{BytesN, Env};

pub const PROOF: [u8; 384] = [
    2, 125, 104, 204, 107, 146, 103, 71, 115, 229, 5, 186, 89, 248, 24, 222, 4, 148, 175, 174, 65,
    47, 67, 139, 114, 41, 219, 176, 118, 51, 112, 38, 174, 250, 189, 93, 89, 178, 159, 80, 122,
    115, 134, 91, 87, 24, 170, 187, 12, 104, 238, 54, 64, 213, 167, 134, 28, 12, 245, 35, 43, 145,
    195, 14, 82, 136, 80, 133, 102, 3, 69, 87, 131, 29, 217, 172, 140, 113, 218, 94, 226, 251, 175,
    55, 147, 130, 4, 179, 118, 32, 63, 38, 140, 223, 224, 173, 24, 110, 74, 201, 66, 172, 63, 49,
    35, 15, 20, 221, 57, 251, 88, 83, 81, 90, 173, 24, 216, 231, 36, 94, 238, 128, 113, 123, 172,
    128, 246, 194, 142, 172, 98, 240, 252, 48, 1, 127, 180, 48, 156, 192, 227, 123, 58, 221, 23, 3,
    53, 218, 141, 138, 38, 222, 97, 177, 175, 94, 35, 158, 164, 92, 78, 27, 130, 238, 21, 118, 188,
    72, 126, 151, 86, 113, 6, 15, 116, 4, 145, 64, 247, 196, 34, 186, 31, 51, 99, 231, 99, 97, 64,
    53, 81, 187, 3, 217, 72, 34, 80, 91, 184, 5, 171, 241, 175, 94, 118, 68, 228, 13, 15, 29, 191,
    23, 154, 203, 19, 43, 46, 168, 138, 102, 1, 80, 45, 19, 146, 175, 243, 6, 227, 94, 176, 173,
    117, 178, 136, 11, 185, 194, 242, 123, 25, 27, 24, 19, 160, 44, 152, 191, 129, 17, 52, 231,
    124, 207, 181, 129, 237, 252, 218, 179, 55, 183, 236, 58, 29, 197, 89, 251, 231, 112, 11, 225,
    9, 143, 252, 77, 209, 56, 165, 132, 86, 84, 124, 232, 54, 84, 100, 19, 23, 68, 0, 165, 88, 120,
    194, 194, 163, 213, 25, 171, 48, 134, 189, 53, 178, 232, 198, 223, 10, 85, 111, 144, 92, 34,
    18, 82, 159, 83, 178, 91, 187, 250, 199, 190, 193, 203, 114, 199, 26, 155, 176, 110, 87, 203,
    213, 229, 18, 76, 79, 237, 237, 145, 158, 89, 210, 25, 159, 131, 116, 39, 206, 149, 60, 112,
    146, 13, 220, 141, 121, 67, 76, 208, 38, 10, 150, 69, 111, 139, 245, 172, 121, 18, 221, 208,
    40, 187, 83, 176, 224, 67, 38, 235, 68, 4,
];

pub const VK: [u8; 872] = [
    9, 76, 8, 210, 209, 21, 206, 62, 1, 39, 93, 115, 243, 132, 68, 105, 158, 173, 107, 71, 140,
    192, 231, 240, 220, 249, 177, 40, 225, 103, 126, 133, 73, 94, 101, 176, 142, 165, 201, 68, 67,
    20, 25, 95, 58, 47, 1, 35, 11, 60, 14, 88, 74, 154, 125, 21, 42, 216, 135, 101, 102, 222, 58,
    189, 54, 112, 30, 251, 34, 197, 63, 24, 169, 74, 230, 232, 227, 236, 149, 162, 133, 191, 116,
    64, 74, 154, 87, 29, 37, 55, 11, 199, 116, 194, 165, 253, 14, 252, 73, 242, 105, 168, 45, 29,
    253, 107, 57, 43, 145, 172, 62, 48, 24, 140, 29, 207, 194, 13, 52, 244, 9, 43, 181, 12, 1, 101,
    142, 14, 50, 54, 3, 82, 125, 196, 38, 113, 200, 26, 85, 8, 227, 57, 153, 1, 25, 197, 6, 166,
    154, 66, 13, 227, 78, 111, 155, 106, 74, 180, 176, 232, 152, 29, 123, 184, 232, 148, 13, 91,
    146, 249, 87, 132, 146, 113, 34, 218, 187, 59, 13, 98, 179, 197, 228, 51, 169, 55, 40, 102,
    152, 37, 77, 19, 13, 175, 53, 56, 171, 166, 73, 234, 13, 158, 101, 205, 38, 48, 69, 37, 193,
    130, 154, 227, 151, 146, 161, 241, 20, 86, 29, 112, 224, 137, 82, 255, 196, 9, 64, 248, 26, 17,
    89, 221, 23, 89, 74, 255, 203, 155, 247, 88, 4, 88, 238, 175, 137, 18, 159, 197, 213, 45, 68,
    240, 195, 20, 80, 52, 115, 222, 44, 25, 15, 68, 220, 157, 8, 124, 107, 30, 110, 96, 18, 203,
    207, 89, 229, 127, 168, 218, 62, 196, 231, 228, 38, 161, 50, 160, 48, 143, 10, 41, 9, 163, 246,
    26, 192, 234, 42, 254, 218, 23, 43, 44, 113, 198, 124, 48, 126, 123, 32, 251, 18, 225, 137,
    195, 106, 114, 40, 74, 35, 15, 53, 189, 152, 80, 38, 136, 139, 251, 108, 95, 32, 226, 35, 243,
    71, 225, 8, 35, 34, 138, 133, 212, 234, 208, 138, 76, 94, 106, 35, 130, 42, 46, 163, 206, 154,
    148, 150, 36, 231, 19, 67, 254, 132, 242, 11, 87, 119, 34, 123, 49, 110, 226, 116, 244, 47,
    174, 155, 223, 202, 144, 14, 223, 53, 179, 16, 230, 151, 121, 97, 119, 251, 63, 18, 106, 210,
    91, 47, 161, 130, 120, 156, 239, 253, 177, 97, 72, 137, 189, 151, 226, 141, 64, 166, 115, 172,
    175, 13, 40, 48, 197, 53, 213, 132, 181, 199, 192, 158, 93, 200, 252, 165, 178, 15, 248, 43,
    11, 81, 144, 86, 215, 149, 232, 20, 103, 120, 153, 190, 20, 92, 81, 188, 122, 54, 70, 79, 110,
    147, 32, 63, 132, 97, 146, 250, 85, 116, 146, 3, 25, 179, 185, 94, 242, 0, 216, 113, 151, 0,
    127, 5, 10, 7, 112, 192, 152, 115, 11, 255, 207, 58, 83, 138, 140, 233, 143, 98, 63, 68, 21,
    102, 210, 148, 137, 163, 135, 241, 77, 111, 150, 138, 168, 73, 233, 90, 103, 158, 9, 242, 126,
    222, 112, 78, 240, 250, 184, 15, 134, 176, 107, 4, 255, 180, 210, 58, 154, 90, 164, 214, 89,
    202, 194, 106, 191, 203, 79, 160, 240, 252, 60, 16, 135, 107, 238, 244, 86, 175, 27, 212, 148,
    45, 73, 206, 30, 75, 163, 51, 147, 0, 135, 209, 159, 40, 167, 243, 184, 90, 222, 19, 115, 231,
    223, 87, 214, 222, 43, 87, 22, 171, 5, 138, 164, 117, 104, 42, 122, 245, 162, 41, 225, 141, 1,
    6, 78, 212, 40, 143, 186, 63, 16, 48, 142, 201, 255, 75, 194, 243, 93, 157, 151, 38, 69, 223,
    223, 95, 58, 25, 119, 217, 6, 129, 80, 123, 41, 57, 128, 170, 115, 137, 196, 229, 182, 56, 4,
    123, 138, 179, 249, 131, 172, 1, 209, 147, 197, 201, 76, 184, 38, 53, 102, 54, 117, 54, 17,
    182, 219, 0, 172, 13, 134, 80, 13, 182, 237, 2, 0, 0, 0, 0, 0, 0, 0, 6, 81, 52, 140, 234, 143,
    163, 204, 77, 226, 181, 205, 29, 59, 193, 187, 44, 242, 232, 137, 163, 157, 177, 129, 240, 108,
    45, 142, 75, 6, 242, 72, 200, 39, 231, 150, 142, 159, 168, 253, 101, 161, 172, 106, 220, 149,
    5, 82, 24, 22, 80, 60, 235, 162, 89, 40, 184, 182, 236, 70, 111, 159, 51, 111, 172, 97, 213,
    75, 90, 145, 61, 200, 228, 240, 91, 36, 83, 181, 211, 169, 213, 58, 18, 147, 233, 238, 169,
    166, 27, 48, 45, 168, 245, 204, 105, 205, 22, 15, 127, 146, 83, 5, 76, 59, 55, 224, 184, 147,
    197, 239, 15, 248, 65, 220, 201, 27, 250, 224, 94, 246, 76, 26, 92, 2, 229, 226, 228, 8, 221,
    84, 127, 21, 126, 50, 154, 94, 145, 142, 159, 248, 193, 82, 122, 227, 6, 148, 203, 236, 56,
    236, 83, 251, 123, 81, 85, 198, 181, 109, 78, 24, 226, 27, 126, 247, 246, 225, 70, 232, 187,
    254, 122, 137, 122, 68, 220, 246, 62, 203, 39, 214, 20, 20, 212, 7, 200, 184, 46, 158, 79, 184,
    16, 109,
];

pub const P1: [u8; 96] = [
    6, 81, 52, 140, 234, 143, 163, 204, 77, 226, 181, 205, 29, 59, 193, 187, 44, 242, 232, 137,
    163, 157, 177, 129, 240, 108, 45, 142, 75, 6, 242, 72, 200, 39, 231, 150, 142, 159, 168, 253,
    101, 161, 172, 106, 220, 149, 5, 82, 24, 22, 80, 60, 235, 162, 89, 40, 184, 182, 236, 70, 111,
    159, 51, 111, 172, 97, 213, 75, 90, 145, 61, 200, 228, 240, 91, 36, 83, 181, 211, 169, 213, 58,
    18, 147, 233, 238, 169, 166, 27, 48, 45, 168, 245, 204, 105, 205,
];

pub const P2: [u8; 96] = [
    22, 15, 127, 146, 83, 5, 76, 59, 55, 224, 184, 147, 197, 239, 15, 248, 65, 220, 201, 27, 250,
    224, 94, 246, 76, 26, 92, 2, 229, 226, 228, 8, 221, 84, 127, 21, 126, 50, 154, 94, 145, 142,
    159, 248, 193, 82, 122, 227, 6, 148, 203, 236, 56, 236, 83, 251, 123, 81, 85, 198, 181, 109,
    78, 24, 226, 27, 126, 247, 246, 225, 70, 232, 187, 254, 122, 137, 122, 68, 220, 246, 62, 203,
    39, 214, 20, 20, 212, 7, 200, 184, 46, 158, 79, 184, 16, 109,
];

#[test]
fn test() {
    let env = Env::default();

    let proof = BytesN::from_array(&env, &PROOF);
    let vk = Bytes::from_slice(&env, [&VK[0..672], &P1, &P2].concat().as_slice());
    let pi = vec![
        &env,
        BytesN::from_array(
            &env,
            &[
                43, 208, 68, 170, 244, 217, 233, 104, 169, 196, 104, 2, 228, 225, 211, 30, 195, 13,
                143, 171, 67, 82, 183, 9, 208, 189, 42, 151, 250, 111, 78, 199,
            ],
        ),
    ];

    let contract_id = env.register(Groth16Contract, ());
    let client = Groth16ContractClient::new(&env, &contract_id);

    let result = client.try_verify(&proof, &vk, &pi);

    assert!(result.is_ok());

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
