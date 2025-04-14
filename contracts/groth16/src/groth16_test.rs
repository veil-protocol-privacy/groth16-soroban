#[cfg(test)]
mod tests {
    extern crate std;

    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, Field};
    use ark_ff::{PrimeField, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;
    use std::ops::MulAssign;
    use std::*;

    #[derive(Copy, Clone)]
    struct MultiplyDemoCircuit<F: PrimeField> {
        a: Option<F>,
        b: Option<F>,
    }

    impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
        for MultiplyDemoCircuit<ConstraintF>
    {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ConstraintF>,
        ) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a.mul_assign(&b);
                Ok(a)
            })?;

            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

            Ok(())
        }
    }

    #[test]
    fn test_groth16_circuit_multiply() {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);

        // generate the setup parameters
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr> { a: None, b: None },
            rng,
        )
        .unwrap();
        for _ in 0..5 {
            let a = BlsFr::rand(rng);
            let b = BlsFr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            // calculate the proof by passing witness variable value
            let proof = Groth16::<Bls12_381>::prove(
                &pk,
                MultiplyDemoCircuit::<BlsFr> {
                    a: Some(a),
                    b: Some(b),
                },
                rng,
            )
            .unwrap();

            // validate the proof
            assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
            assert!(!Groth16::<Bls12_381>::verify(&vk, &[a], &proof).unwrap());
        }
    }

    #[test]
    fn test_serde_groth16() {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);

        // generate the setup parameters
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr> { a: None, b: None },
            rng,
        )
        .unwrap();

        let a = BlsFr::rand(rng);
        let b = BlsFr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);

        println!("c {:?}", c.into_bigint().to_bytes_be());

        // calculate the proof by passing witness variable value
        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            MultiplyDemoCircuit::<BlsFr> {
                a: Some(a),
                b: Some(b),
            },
            rng,
        )
        .unwrap();

        let mut serialized = vec![0; proof.serialized_size(ark_serialize::Compress::No)];
        proof.serialize_uncompressed(&mut serialized[..]).unwrap();
        println!("proof {:?}", serialized);

        // println!("proof: {:?}", proof.serialized_size());
        // println!("proof: {:?}", serialized);

        let pr =
            <Groth16<Bls12_381> as SNARK<BlsFr>>::Proof::deserialize_uncompressed(&serialized[..])
                .unwrap();
        assert_eq!(proof, pr);

        let mut serialized = vec![0; pk.serialized_size(ark_serialize::Compress::No)];
        pk.serialize_uncompressed(&mut serialized[..]).unwrap();

        // println!("pk-size: {:?}", pk.serialized_size());
        // println!("pk: {:?}", serialized);
        let p = <Groth16<Bls12_381> as SNARK<BlsFr>>::ProvingKey::deserialize_uncompressed(
            &serialized[..],
        )
        .unwrap();
        assert_eq!(pk, p);

        let mut serialized = vec![0; vk.serialized_size(ark_serialize::Compress::No)];
        vk.serialize_uncompressed(&mut serialized[..]).unwrap();
        println!("vk {:?}", serialized);

        for i in 0..vk.gamma_abc_g1.len() {
            let mut serialized =
                vec![0; vk.gamma_abc_g1[i].serialized_size(ark_serialize::Compress::No)];
            vk.gamma_abc_g1[i]
                .serialize_uncompressed(&mut serialized[..])
                .unwrap();
            println!("i[{}]: {:?}", i, serialized);
        }

        // println!("vk-size: {:?}", vk.serialized_size());
        // println!("vk: {:?}", serialized);

        let v = <Groth16<Bls12_381> as SNARK<BlsFr>>::VerifyingKey::deserialize_uncompressed(
            &serialized[..],
        )
        .unwrap();
        assert_eq!(vk, v);

        assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
        assert!(Groth16::<Bls12_381>::verify(&v, &[c], &pr).unwrap());
    }

    #[test]
    fn test_self_implement_verifier() {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);

        // generate the setup parameters
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr> { a: None, b: None },
            rng,
        )
        .unwrap();
        for _ in 0..5 {
            let a = BlsFr::rand(rng);
            let b = BlsFr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            // calculate the proof by passing witness variable value
            let proof = Groth16::<Bls12_381>::prove(
                &pk,
                MultiplyDemoCircuit::<BlsFr> {
                    a: Some(a),
                    b: Some(b),
                },
                rng,
            )
            .unwrap();

            // validate the proof
            let mut acc = vk.gamma_abc_g1[0].into_group();
            for (i, input) in [c].iter().enumerate() {
                acc += vk.gamma_abc_g1[i + 1].into_group() * input;
            }
            let acc = acc.into_affine();

            assert!(
                Bls12_381::multi_pairing(
                    [proof.a, -vk.alpha_g1, -acc, -proof.c],
                    [proof.b, vk.beta_g2, vk.gamma_g2, vk.delta_g2],
                )
                .0 == <Bls12_381 as Pairing>::TargetField::ONE,
            );
        }
    }
}


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
