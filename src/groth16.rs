//! We have to implement a lot of the Groth16 API because we need verification keys to strore
//! [δ]₁ as well as the generator of G1. We also need to make sure that γ = 1.

use crate::util::get_group_generators;

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, PrimeField, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, Result as R1CSResult, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::rand::Rng;
use core::ops::AddAssign;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct ProvingKey<E: PairingEngine> {
    /// The underlying proving key
    pub ark_pk: ark_groth16::ProvingKey<E>,
    /// The generator we chose for `E::G1`
    pub g1_gen: E::G1Projective,
}

impl<E: PairingEngine> ProvingKey<E> {
    pub fn verifying_key(&self) -> VerifyingKey<E> {
        let ark_pvk = ark_groth16::prepare_verifying_key(&self.ark_pk.vk);
        VerifyingKey {
            ark_pvk,
            g1_gen: self.g1_gen,
            delta_g1: self.ark_pk.delta_g1.into(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Proof<E: PairingEngine>(pub ark_groth16::Proof<E>);

impl<E: PairingEngine> Default for Proof<E> {
    fn default() -> Proof<E> {
        Proof(ark_groth16::Proof::default())
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct BlindedProof<E: PairingEngine>(pub ark_groth16::Proof<E>);

#[derive(Clone, Debug)]
pub struct VerifyingKey<E: PairingEngine> {
    pub ark_pvk: ark_groth16::PreparedVerifyingKey<E>,
    pub g1_gen: E::G1Projective,
    pub delta_g1: E::G1Projective,
}

pub fn generate_random_parameters<E, C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<ProvingKey<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    // We need γ = 1 for linkage to work. This does not affect the soundness or ZK of the scheme
    // (see section XXX of the paper).
    let gamma = E::Fr::one();

    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let delta = E::Fr::rand(rng);
    let (g1_gen, g2_gen) = get_group_generators::<E>();

    let ark_pk = ark_groth16::generator::generate_parameters::<E, C, R>(
        circuit, alpha, beta, gamma, delta, g1_gen, g2_gen, rng,
    )?;

    Ok(ProvingKey { ark_pk, g1_gen })
}

pub fn create_random_proof<E, C, R>(
    circuit: C,
    pk: &ProvingKey<E>,
    rng: &mut R,
) -> Result<Proof<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    ark_groth16::create_random_proof::<E, C, R>(circuit, &pk.ark_pk, rng).map(Proof)
}

pub fn verify_proof<E: PairingEngine>(
    pvk: &VerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> R1CSResult<bool> {
    ark_groth16::verify_proof(&pvk.ark_pvk, &proof.0, public_inputs)
}

// Prepares public inputs for verification. If the number of provided field elements is less than
// the number of circuit public inputs, we assume it's because those are hidden and we pad it with
// leading 0s.
pub fn prepare_inputs<E: PairingEngine>(
    pvk: &VerifyingKey<E>,
    public_inputs: &[E::Fr],
) -> Result<E::G1Projective, SynthesisError> {
    let pvk = &pvk.ark_pvk;
    let mut g_ic = pvk.vk.gamma_abc_g1[0].into_projective();

    if (public_inputs.len() + 1) > pvk.vk.gamma_abc_g1.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    // Collect inputs in reverse, stopping when we run out. This is the same as padding with
    // leading 0s.
    for (i, b) in public_inputs
        .iter()
        .rev()
        .zip(pvk.vk.gamma_abc_g1.iter().rev())
    {
        g_ic.add_assign(&b.mul(i.into_repr()));
    }

    Ok(g_ic)
}
