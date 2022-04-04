use linkg16::groth16::*;

use ark_bls12_381::Bls12_381 as F;
use ark_crypto_primitives::prf::{
    blake2s::{constraints::Blake2sGadget, Blake2s},
    PRFGadget, PRF,
};
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::ToBytesGadget, eq::EqGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, ToConstraintField},
};
use ark_std::rand::Rng;
use criterion::{criterion_group, criterion_main, Criterion};

type Fr = <F as PairingEngine>::Fr;

/// Depending on use_ki, this circuit will do one of three things:
///   If use_ki = 1 this circuit proves `H(domain_str, k1) = digest`, where
///     all variables are public input.
///   If use_ki = 2 this circuit proves `H(domain_str, k2) = digest`, where
///     all variables are public input.
///   If use_ki = 3 is set, this circuit proves `H(H(domain_str, k1), k2) = digest`, where
///     all variables are public input.
/// Later, we will make `k1` and `k2` hidden by the Groth-Sahai proof.
#[derive(Clone)]
struct HashPreimageCircuit<ConstraintF: Field> {
    use_ki: usize,
    k1: ConstraintF,
    k2: ConstraintF,
    domain_str: [u8; 32],
    digest: [u8; 32],
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for HashPreimageCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Get k1,k2 as PUBLIC input
        let k1 = FpVar::<ConstraintF>::new_input(ns!(cs, "preimage"), || Ok(self.k1))?;
        let k2 = FpVar::<ConstraintF>::new_input(ns!(cs, "preimage"), || Ok(self.k2))?;

        // Get the domain str and hash as well
        let domain_str: Vec<UInt8<ConstraintF>> =
            UInt8::new_input_vec(ns!(cs, "domain_str"), &self.domain_str)?;
        let expected_digest = UInt8::new_input_vec(ns!(cs, "digest"), &self.digest)?;

        let computed_digest = match self.use_ki {
            1 => {
                // Compute `H(domain_str, k1)`
                Blake2sGadget::evaluate(&domain_str, &k1.to_bytes()?)?
            }
            2 => {
                // Compute `H(domain_str, k2)`
                Blake2sGadget::evaluate(&domain_str, &k2.to_bytes()?)?
            }
            3 => {
                // Compute `H(H(domain_str, k1), k2)`
                let inner_digest = Blake2sGadget::evaluate(&domain_str, &k1.to_bytes()?)?;
                Blake2sGadget::evaluate(&inner_digest.0, &k2.to_bytes()?)?
            }
            _ => panic!("use_ki must be 1, 2, or 3"),
        };
        // Enforce that the provided digest equals the computed one
        expected_digest.enforce_equal(&computed_digest.0)
    }
}

impl<ConstraintF: PrimeField> HashPreimageCircuit<ConstraintF> {
    /// Generates a proving key for this circuit for a specific choice of use_ki
    fn gen_crs<E, R>(rng: &mut R, use_ki: usize) -> ProvingKey<E>
    where
        E: PairingEngine<Fr = ConstraintF>,
        R: Rng,
    {
        let placeholder_bytes = *b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let placeholder_circuit = HashPreimageCircuit {
            use_ki,
            k1: E::Fr::zero(),
            k2: E::Fr::zero(),
            domain_str: placeholder_bytes,
            digest: placeholder_bytes,
        };
        generate_random_parameters::<E, _, _>(placeholder_circuit, rng).unwrap()
    }

    /// Proves this circuit with the given inputs. Returns the serialized public inputs and the
    /// Groth16 proof.
    fn prove<E, R>(
        rng: &mut R,
        pk: &ProvingKey<E>,
        use_ki: usize,
        k1: E::Fr,
        k2: E::Fr,
        domain_str: [u8; 32],
    ) -> (Vec<ConstraintF>, Proof<E>)
    where
        E: PairingEngine<Fr = ConstraintF>,
        R: Rng,
    {
        // Compute the digest we need to prove
        let mut k1_bytes = [0u8; 32];
        let mut k2_bytes = [0u8; 32];
        k1_bytes.copy_from_slice(&k1.into_repr().to_bytes_le());
        k2_bytes.copy_from_slice(&k2.into_repr().to_bytes_le());
        let digest = match use_ki {
            1 => {
                // H(domain_str, k1)
                Blake2s::evaluate(&domain_str, &k1_bytes).unwrap()
            }
            2 => {
                // H(domain_str, k2)
                Blake2s::evaluate(&domain_str, &k2_bytes).unwrap()
            }
            3 => {
                // H(H(domain_str, k1), k2)
                let inner_digest = Blake2s::evaluate(&domain_str, &k1_bytes).unwrap();
                Blake2s::evaluate(&inner_digest, &k2_bytes).unwrap()
            }
            _ => {
                panic!("use_ki must be 1, 2, or 3");
            }
        };

        // Make the circuit and prove it
        let circuit = HashPreimageCircuit {
            use_ki,
            k1,
            k2,
            domain_str,
            digest,
        };
        let proof = create_random_proof::<E, _, _>(circuit, pk, rng).unwrap();

        // Serialize all the public inputs
        let public_inputs = [
            k1.to_field_elements().unwrap(),
            k2.to_field_elements().unwrap(),
            domain_str.to_field_elements().unwrap(),
            digest.to_field_elements().unwrap(),
        ]
        .concat();

        (public_inputs, proof)
    }
}

/// In this test we make three circuits. One computes `H(domain_str1, k1)`. One computes
/// `H(H(domain_str2, k1), k2)`. One computes `H(domain_str1, k2)`. We then prove that all of
/// these circuits share the same `k1,k2`.
fn bench_link(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // Set the parameters of this circuit
    let k1 = Fr::from(1337u32);
    let k2 = Fr::from(0xdeadbeefu32);
    let domain_str1 = *b"goodbye my coney island babyyyyy";
    let domain_str2 = *b"goodbye my one true loveeeeeeeee";

    let hidden_inputs = &[k1, k2];
    let num_hidden_inputs = hidden_inputs.len();

    // Generate the CRSs and then prove on the above parameters. single1 is the circuit that
    // computes `H(domain_str1, k1)`. single2 computes `H(domain_str1, k2)`. double computes
    // `H(H(domain_str2, k1), k2)`.
    let pk_single1 = HashPreimageCircuit::gen_crs::<F, _>(&mut rng, 1);
    let pk_single2 = HashPreimageCircuit::gen_crs::<F, _>(&mut rng, 2);
    let pk_double = HashPreimageCircuit::gen_crs::<F, _>(&mut rng, 3);
    let (public_inputs_single1, proof_single1) =
        HashPreimageCircuit::prove(&mut rng, &pk_single1, 1, k1, k2, domain_str1);
    let (public_inputs_single2, proof_single2) =
        HashPreimageCircuit::prove(&mut rng, &pk_single2, 2, k1, k2, domain_str1);
    let (public_inputs_double, proof_double) =
        HashPreimageCircuit::prove(&mut rng, &pk_double, 3, k1, k2, domain_str2);

    // Verify the proofs naively. This is just a sanity check
    let vk_single1 = pk_single1.verifying_key();
    let vk_single2 = pk_single2.verifying_key();
    let vk_double = pk_double.verifying_key();
    assert!(verify_proof(&vk_single1, &proof_single1, &public_inputs_single1).unwrap());
    assert!(verify_proof(&vk_single2, &proof_single2, &public_inputs_single2).unwrap());
    assert!(verify_proof(&vk_double, &proof_double, &public_inputs_double).unwrap());

    // Now the linkage test. Construct a linkage proof
    c.bench_function("Link: Proving 3 proofs all share 2 inputs", |b| {
        b.iter(|| {
            linkg16::link(
                &mut rng,
                &[
                    (&vk_single1, &proof_single1),
                    (&vk_single2, &proof_single2),
                    (&vk_double, &proof_double),
                ],
                hidden_inputs,
            )
        })
    });

    let link_proof = linkg16::link(
        &mut rng,
        &[
            (&vk_single1, &proof_single1),
            (&vk_single2, &proof_single2),
            (&vk_double, &proof_double),
        ],
        hidden_inputs,
    );

    // Now the veriifer checks the proofs. Note, the verifier does not know the common inputs,
    // and so we slice those out.
    let prepared_input_single1 =
        prepare_inputs(&vk_single1, &public_inputs_single1[num_hidden_inputs..]).unwrap();
    let prepared_input_single2 =
        prepare_inputs(&vk_single2, &public_inputs_single2[num_hidden_inputs..]).unwrap();
    let prepared_input_double =
        prepare_inputs(&vk_double, &public_inputs_double[num_hidden_inputs..]).unwrap();

    c.bench_function("Link: Verifying 3 proofs all share 2 inputs", |b| {
        b.iter(|| {
            assert!(linkg16::verify_link(
                &link_proof,
                &[
                    (&vk_single1, &prepared_input_single1),
                    (&vk_single2, &prepared_input_single2),
                    (&vk_double, &prepared_input_double)
                ],
            )
            .unwrap())
        })
    });
}

criterion_group!(benches, bench_link);

criterion_main!(benches);
