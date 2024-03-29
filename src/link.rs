//! Defines the `link` function

use crate::{
    groth16::*,
    multi_dleq::{prove_multi_dleq, verify_multi_dleq, MultiDleqProof},
    util::dot_prod,
};

use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::{CryptoRng, Rng};
use merlin::Transcript;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct LinkedProof<E: PairingEngine> {
    pub mdleq_proof: MultiDleqProof<E::G1Projective>,
    pub blinded_proofs: Vec<BlindedProof<E>>,
    pub blinded_wires: Vec<E::G1Projective>,
}

impl<E: PairingEngine> LinkedProof<E> {
    fn num_linked_proofs(&self) -> usize {
        self.mdleq_proof.resp.1.len()
    }

    fn num_hidden_inputs(&self) -> usize {
        self.mdleq_proof.resp.0.len()
    }
}

/// Link Groth16 proofs, given a list of common inputs as well as a list of the underlying proofs
/// with their corresponding CRS. If `n` common inputs are given, they MUST be the first `n` public
/// inputs of the circuits, in the order they are witnessed.
pub fn link<E, R>(
    rng: &mut R,
    data: &[(&VerifyingKey<E>, &Proof<E>)],
    common_inputs: &[E::Fr],
) -> LinkedProof<E>
where
    E: PairingEngine,
    R: Rng + CryptoRng,
{
    // Make a new transcript and call `link_wt`
    let mut transcript = Transcript::new(b"toplevel LinkG16");
    link_wt(rng, &mut transcript, data, common_inputs)
}

/// Verify linked Groth16 proofs, given a linkage proof, the proofs' CRSs, and the proofs' prepared
/// public inputs.
pub fn verify_link<E: PairingEngine>(
    proof: &LinkedProof<E>,
    data: &[(&VerifyingKey<E>, &E::G1Projective)],
) -> Result<bool, SynthesisError> {
    // Make a new transcript and call `verify_link_wt`
    let mut transcript = Transcript::new(b"toplevel LinkG16");
    verify_link_wt(&mut transcript, proof, data)
}

/// Link Groth16 proofs, given a list of common inputs as well as a list of the underlying proofs
/// with their corresponding CRS. If `n` common inputs are given, they MUST be the first `n` public
/// inputs of the circuits, in the order they are witnessed. This takes a `Transcript` parameter,
/// meaning it can be used as a subprotocol inside a larger noninteractive protocol.
pub fn link_wt<E, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    data: &[(&VerifyingKey<E>, &Proof<E>)],
    common_inputs: &[E::Fr],
) -> LinkedProof<E>
where
    E: PairingEngine,
    R: Rng + CryptoRng,
{
    let num_proofs = data.len();
    let num_common_inputs = common_inputs.len();

    // Sample the blinders zⱼ
    let zz: Vec<E::Fr> = core::iter::repeat_with(|| E::Fr::rand(rng))
        .take(num_proofs)
        .collect();

    // Collect the values
    // {W₀{(1)}, ..., W_{t-1}^{(1)}},
    // ...
    // {W₀{(k)}, ..., W_{t-1}^{(k)}},
    let www: Vec<Vec<E::G1Projective>> = data
        .iter()
        .map(|(vk, _)| {
            vk.ark_pvk.vk.gamma_abc_g1[1..1 + num_common_inputs]
                .iter()
                .cloned()
                .map(E::G1Projective::from)
                .collect()
        })
        .collect();

    // Collect the [δ]₁^{(j)} values
    let deltas: Vec<E::G1Projective> = data.iter().map(|(vk, _)| vk.delta_g1).collect();

    // Commit to the common input for each circuit, Uⱼ := Σ aᵢWᵢ^(j) + zⱼ[δ]₁^(j)
    let blinded_wires: Vec<E::G1Projective> = www
        .iter()
        .zip(deltas.iter())
        .zip(zz.iter())
        .map(|((ww, d), z)| dot_prod(common_inputs, ww) + d.mul(z))
        .collect();

    // Prove that uu are well-formed
    let mdleq_proof = prove_multi_dleq(
        rng,
        transcript,
        &blinded_wires,
        &www,
        &deltas,
        common_inputs,
        &zz,
    );

    // Now rerandomize and blind the proofs. Specifically, for each proof (Aⱼ, Bⱼ, Cⱼ), set
    // Cⱼ' := Cⱼ - zⱼGⱼ where Gⱼ is the G1 generator
    let blinded_proofs: Vec<_> = data
        .iter()
        .zip(zz.iter())
        .map(|((vk, proof), z)| {
            let mut proof = ark_groth16::rerandomize_proof(rng, &vk.ark_pvk.vk, &proof.0);
            // C' = C - zG
            let new_c = proof.c.into_projective() - vk.g1_gen.mul(z.into_repr());
            proof.c = new_c.into_affine();
            BlindedProof(proof)
        })
        .collect();

    LinkedProof {
        mdleq_proof,
        blinded_proofs,
        blinded_wires,
    }
}

/// Verify linked Groth16 proofs, given a linkage proof, the proofs' CRSs, and the proofs' prepared
/// public inputs. This takes a `Transcript` parameter, meaning it can be used as a subprotocol
/// inside a larger noninteractive protocol.
pub fn verify_link_wt<E: PairingEngine>(
    transcript: &mut Transcript,
    proof: &LinkedProof<E>,
    data: &[(&VerifyingKey<E>, &E::G1Projective)],
) -> Result<bool, SynthesisError> {
    let num_proofs = proof.num_linked_proofs();
    let num_common_inputs = proof.num_hidden_inputs();

    // Check that the data we're getting matches the number of Groth16 proofs wrapped
    assert_eq!(data.len(), num_proofs);

    let LinkedProof {
        mdleq_proof,
        blinded_proofs,
        blinded_wires,
    } = proof;

    // Collect the values
    // {W₀{(1)}, ..., W_{t-1}^{(1)}},
    // ...
    // {W₀{(k)}, ..., W_{t-1}^{(k)}},
    let www: Vec<Vec<E::G1Projective>> = data
        .iter()
        .map(|(vk, _)| {
            vk.ark_pvk.vk.gamma_abc_g1[1..1 + num_common_inputs]
                .iter()
                .cloned()
                .map(E::G1Projective::from)
                .collect()
        })
        .collect();
    let deltas: Vec<E::G1Projective> = data.iter().map(|(vk, _)| vk.delta_g1).collect();
    if !verify_multi_dleq(transcript, mdleq_proof, blinded_wires, &www, &deltas) {
        return Ok(false);
    }

    // Now check all the equations wrt inputs blinded_wire + given_input
    for ((blind_wire, proof), (vk, pub_input)) in blinded_wires
        .iter()
        .zip(blinded_proofs.iter())
        .zip(data.iter())
    {
        let proof_input = *blind_wire + *pub_input;
        if !ark_groth16::verify_proof_with_prepared_inputs(&vk.ark_pvk, &proof.0, &proof_input)? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    type Fr = <F as PairingEngine>::Fr;

    // Does a round trip serialization -> deserialization on a given value. This should be able to
    // be sprinkled in anywhere without changing behavior
    fn serialization_roundtrip<T>(val: &mut T)
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        // Do a round trip for uncompressed/unchecked ser/deser
        {
            let mut buf = Vec::new();
            val.serialize_uncompressed(&mut buf).unwrap();

            let mut cursor = buf.as_slice();
            *val = T::deserialize_unchecked(&mut cursor).unwrap();
        }

        // Now do a round trip for compressed/checked ser/deser
        {
            let mut buf = Vec::new();
            val.serialize(&mut buf).unwrap();

            let mut cursor = buf.as_slice();
            *val = T::deserialize(&mut cursor).unwrap();
        }
    }

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

    /// We test the preimage circuit here
    #[test]
    fn test_preimage_circuit_correctness() {
        let mut rng = ark_std::test_rng();

        // Set the parameters of this circuit. Do the full double-hash, i.e., use_ki = 3
        let use_ki = 3;
        let domain_str = *b"goodbye my coney island babyyyyy";
        let k1 = Fr::from(1337u32);
        let k2 = Fr::from(0xdeadbeefu32);

        // Generate the CRS and then prove on the above parameters
        let pk = HashPreimageCircuit::gen_crs::<F, _>(&mut rng, use_ki);
        let (public_inputs, proof) =
            HashPreimageCircuit::prove(&mut rng, &pk, use_ki, k1, k2, domain_str);

        // Now verify the proof
        let mut vk = pk.verifying_key();
        {
            // serialize -> deserialize; should be a no-op
            serialization_roundtrip(&mut vk);
        }
        assert!(verify_proof(&vk, &proof, &public_inputs).unwrap());
    }

    /// In this test we make three circuits. One computes `H(domain_str1, k1)`. One computes
    /// `H(H(domain_str2, k1), k2)`. One computes `H(domain_str1, k2)`. We then prove that all of
    /// these circuits share the same `k1,k2`.
    #[test]
    fn test_preimage_circuit_linkage() {
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
        let mut vk_single1 = pk_single1.verifying_key();
        let mut vk_single2 = pk_single2.verifying_key();
        let mut vk_double = pk_double.verifying_key();
        {
            // serialize -> deserialize; should be a no-op
            serialization_roundtrip(&mut vk_single1);
            serialization_roundtrip(&mut vk_single2);
            serialization_roundtrip(&mut vk_double);
        }
        assert!(verify_proof(&vk_single1, &proof_single1, &public_inputs_single1).unwrap());
        assert!(verify_proof(&vk_single2, &proof_single2, &public_inputs_single2).unwrap());
        assert!(verify_proof(&vk_double, &proof_double, &public_inputs_double).unwrap());

        // Now the linkage test. Construct a linkage proof
        let link_proof = link(
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

        assert!(verify_link(
            &link_proof,
            &[
                (&vk_single1, &prepared_input_single1),
                (&vk_single2, &prepared_input_single2),
                (&vk_double, &prepared_input_double)
            ],
        )
        .unwrap());
    }
}
