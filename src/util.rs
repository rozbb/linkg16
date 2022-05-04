use ark_ec::{group::Group, PairingEngine};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};

// Deterministically get generators for E::G1 and E::G2
pub(crate) fn get_group_generators<E: PairingEngine>() -> (E::G1Projective, E::G2Projective) {
    // A nothing-up-my-sleeve seed
    let mut seed = [0u8; 32];
    seed[0..18].copy_from_slice(b"linkg16-generators");
    let mut rng = StdRng::from_seed(seed);

    (
        E::G1Projective::rand(&mut rng),
        E::G2Projective::rand(&mut rng),
    )
}

// Computes the dot product rr·gg where rr are scalars and gg are group elements
pub(crate) fn dot_prod<G: Group>(rr: &[G::ScalarField], gg: &[G]) -> G {
    rr.iter().zip(gg.iter()).map(|(r, g)| g.mul(r)).sum()
}

// Convenience functions for generateing Fiat-Shamir challenges
pub(crate) trait TranscriptProtocol {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized;

    /// Appends multiple CanonicalSerialize-able element to the transcript. Panics on serialization
    /// error.
    fn append_multi_serializable<S>(&mut self, label: &'static [u8], vals: &[S])
    where
        S: CanonicalSerialize;

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for merlin::Transcript {
    /// Appends a CanonicalSerialize-able element to the transcript. Panics on serialization error.
    fn append_serializable<S>(&mut self, label: &'static [u8], val: &S)
    where
        S: CanonicalSerialize + ?Sized,
    {
        // Serialize the input and give it to the transcript
        let mut buf = Vec::new();
        val.serialize(&mut buf)
            .expect("serialization error in transcript");
        self.append_message(label, &buf);
    }

    /// Appends multiple CanonicalSerialize-able element to the transcript. Panics on serialization
    /// error.
    fn append_multi_serializable<S>(&mut self, label: &'static [u8], vals: &[S])
    where
        S: CanonicalSerialize,
    {
        for val in vals {
            self.append_serializable(label, val);
        }
    }

    /// Produces a pseudorandom field element from the current transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        // Fill a buf with random bytes
        let mut buf = <<StdRng as SeedableRng>::Seed as Default>::default();
        self.challenge_bytes(label, &mut buf);

        // Use the buf to make an RNG. Then use that RNG to generate a field element
        let mut rng = StdRng::from_seed(buf);
        F::rand(&mut rng)
    }
}
