use crate::util::TranscriptProtocol;

use std::io::{Read, Write};

use ark_ec::group::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use merlin::Transcript;

const DOMAIN_STR: &[u8] = b"LinkG16-multi-dleq";

/// Hidden Wire Well-formedness proof. Encodes a sigma proof for the relation
/// ZK { ({Uⱼ, Gⱼ, Hⱼ}; w, {xⱼ}) : ∧ Uⱼ = wGⱼ+xⱼHⱼ }
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub(crate) struct MultiDleqProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    pub(crate) coms: Vec<G>,
    pub(crate) resp: (G::ScalarField, Vec<G::ScalarField>),
}

/// Proves ZK { ({Uⱼ, Gⱼ, Hⱼ}; w, {xⱼ}) : ∧ Uⱼ = wGⱼ+xⱼHⱼ }. Uses the context provided by
/// `transcript` to create the ZK challenge.
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub(crate) fn prove_multi_dleq<G, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    uu: &[G],
    gg: &[G],
    hh: &[G],
    w: &G::ScalarField,
    xx: &[G::ScalarField],
) -> MultiDleqProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
    R: CryptoRng + Rng,
{
    // Make sure all the inputs are the same size
    let k = uu.len();
    assert_eq!(k, gg.len());
    assert_eq!(k, hh.len());
    assert_eq!(k, xx.len());

    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", DOMAIN_STR);

    // Make sure the statement is true
    for (u, (g, (h, x))) in uu.iter().zip(gg.iter().zip(hh.iter().zip(xx.iter()))) {
        assert_eq!(u, &(g.mul(w) + h.mul(x)));
    }

    // Pick random r, {sⱼ}
    let r = G::ScalarField::rand(rng);
    let ss: Vec<_> = core::iter::repeat_with(|| G::ScalarField::rand(rng))
        .take(k)
        .collect();
    // Construct commitments comⱼ = rGⱼ + sⱼHⱼ
    let coms = ss
        .iter()
        .zip(gg.iter().zip(hh.iter()))
        .map(|(s, (g, h))| g.mul(&r) + h.mul(s))
        .collect();

    // Update the transcript
    transcript.append_serializable(b"uu", uu);
    transcript.append_serializable(b"gg", gg);
    transcript.append_serializable(b"hh", hh);
    transcript.append_serializable(b"coms", &coms);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Respond with r' = r - cw and sⱼ' = sⱼ - cxⱼ
    let rp = r - c * w;
    let sps = ss.iter().zip(xx.iter()).map(|(&s, x)| s - c * x).collect();

    MultiDleqProof {
        coms,
        resp: (rp, sps),
    }
}

/// Proves ZK { ({Uⱼ, Gⱼ, Hⱼ}; w, {xⱼ}) : ∧ Uⱼ = wGⱼ+xⱼHⱼ }. Uses the context provided by the
/// context provided by `transcript` to create the ZK challenge.
#[must_use]
pub(crate) fn verify_multi_dleq<G>(
    transcript: &mut Transcript,
    proof: &MultiDleqProof<G>,
    uu: &[G],
    gg: &[G],
    hh: &[G],
) -> bool
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", DOMAIN_STR);

    let coms = &proof.coms;

    // Update the transcript
    transcript.append_serializable(b"uu", uu);
    transcript.append_serializable(b"gg", gg);
    transcript.append_serializable(b"hh", hh);
    transcript.append_serializable(b"coms", coms);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Check that comⱼ == r'Gⱼ + sⱼHⱼ + cUⱼ
    let (rp, sps) = &proof.resp;
    coms.iter()
        .zip(sps.iter().zip(gg.iter().zip(hh.iter().zip(uu.iter()))))
        .all(|(&com, (s, (g, (h, u))))| com == g.mul(rp) + h.mul(s) + u.mul(&c))
}

#[test]
fn test_multi_dleq_correctness() {
    use ark_ec::PairingEngine;

    type F = <G as Group>::ScalarField;
    type G = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective;

    const K: usize = 10;

    // Pick the public elements
    let mut rng = ark_std::test_rng();
    let gg: Vec<_> = core::iter::repeat_with(|| G::rand(&mut rng))
        .take(K)
        .collect();
    let hh: Vec<_> = core::iter::repeat_with(|| G::rand(&mut rng))
        .take(K)
        .collect();

    // Pick the witnesses
    let w = F::rand(&mut rng);
    let xx: Vec<_> = core::iter::repeat_with(|| F::rand(&mut rng))
        .take(K)
        .collect();

    // Compute the curve points using the witnesses
    let uu: Vec<_> = gg
        .iter()
        .zip(hh.iter().zip(xx.iter()))
        .map(|(g, (h, x))| g.mul(&w) + h.mul(x))
        .collect();

    // Make an empty transcript for proving, and prove the relation
    let mut proving_transcript = Transcript::new(b"test_multi_dleq_correctness");
    let proof = prove_multi_dleq(&mut rng, &mut proving_transcript, &uu, &gg, &hh, &w, &xx);

    // Now make an empty transcript for verifying, and verify the relation
    let mut verifying_transcript = Transcript::new(b"test_multi_dleq_correctness");
    assert!(verify_multi_dleq(
        &mut verifying_transcript,
        &proof,
        &uu,
        &gg,
        &hh,
    ));
}
