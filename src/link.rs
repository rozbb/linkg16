use crate::{
    groth16::*,
    multi_dleq::{prove_multi_dleq, verify_multi_dleq, MultiDleqProof},
};

use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::{CryptoRng, Rng};
use merlin::Transcript;

pub struct LinkedProof<E: PairingEngine> {
    pub mdleq_proof: MultiDleqProof<E::G1Projective>,
    pub blinded_proofs: Vec<BlindedProof<E>>,
    pub blinded_wires: Vec<E::G1Projective>,
}

// Link Groth16 proofs (with transcript)
pub fn link_wt<E, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    data: &[(&VerifyingKey<E>, &Proof<E>, &E::G1Projective)],
    common_input: E::Fr,
) -> LinkedProof<E>
where
    E: PairingEngine,
    R: Rng + CryptoRng,
{
    let num_proofs = data.len();

    // Sample the blinders zⱼ
    let zz: Vec<E::Fr> = core::iter::repeat_with(|| E::Fr::rand(rng))
        .take(num_proofs)
        .collect();

    // Collect the W₀^(j) values
    let ww: Vec<E::G1Projective> = data
        .iter()
        .map(|(vk, _, _)| vk.ark_vk.gamma_abc_g1[1].into())
        .collect();
    let deltas: Vec<E::G1Projective> = data.iter().map(|(vk, _, _)| vk.delta_g1).collect();

    // Commit to the common input for each circuit, Uⱼ := a₀W₀^(j) + zⱼ[δ]₁^(j)
    let blinded_wires: Vec<E::G1Projective> = ww.iter().map(|w| w.mul(&common_input)).collect();

    // Prove that uu are well-formed
    let mdleq_proof = prove_multi_dleq(
        rng,
        transcript,
        &blinded_wires,
        &ww,
        &deltas,
        &common_input,
        &zz,
    );

    // Now rerandomize and blind the proofs. Specifically, for each proof (Aⱼ, Bⱼ, Cⱼ), set
    // Cⱼ' := Cⱼ - zⱼGⱼ where Gⱼ is the G1 generator
    let blinded_proofs: Vec<_> = data
        .iter()
        .zip(zz.iter())
        .map(|((vk, proof, _), z)| {
            let mut proof = ark_groth16::rerandomize_proof(rng, &vk.ark_vk, &proof.0);
            // C' = C - zG
            let new_c = proof.c.into_projective() - vk.g1_generator.mul(z.into_repr());
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

pub fn verify_link_wt<E: PairingEngine>(
    transcript: &mut Transcript,
    proof: &LinkedProof<E>,
    data: &[(&PreparedVerifyingKey<E>, &E::G1Projective)],
) -> Result<bool, SynthesisError> {
    let LinkedProof {
        mdleq_proof,
        blinded_proofs,
        blinded_wires,
    } = proof;

    // First check the multidleq proof. Collect the wires and the deltas
    let ww: Vec<E::G1Projective> = data
        .iter()
        .map(|(pvk, _)| pvk.ark_pvk.vk.gamma_abc_g1[1].into())
        .collect();
    let deltas: Vec<E::G1Projective> = data.iter().map(|(vk, _)| vk.delta_g1).collect();
    if !verify_multi_dleq(transcript, mdleq_proof, blinded_wires, &ww, &deltas) {
        return Ok(false);
    }

    // Now check all the equations wrt inputs blinded_wire + given_input
    for ((blind_wire, proof), (pvk, pub_input)) in blinded_wires
        .iter()
        .zip(blinded_proofs.iter())
        .zip(data.iter())
    {
        let proof_input = *blind_wire + *pub_input;
        if !ark_groth16::verify_proof_with_prepared_inputs(&pvk.ark_pvk, &proof.0, &proof_input)? {
            return Ok(false);
        }
    }

    Ok(true)
}
