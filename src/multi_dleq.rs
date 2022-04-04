use crate::util::{dot_prod, TranscriptProtocol};

use ark_ec::group::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand,
};
use merlin::Transcript;

const DOMAIN_STR: &[u8] = b"LinkG16-multi-dleq";

/// Hidden Wire Well-formedness proof. Encodes a sigma proof for the relation
/// ZK { ({Uⱼ, Gᵢⱼ, Hⱼ}; {wᵢ}_{i=0}^{t-1}, {xⱼ}_{j=1}^k) : ∧ Uⱼ = xⱼHⱼ + Σ wᵢGᵢⱼ }
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct MultiDleqProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    pub coms: Vec<G>,
    pub resp: (Vec<G::ScalarField>, Vec<G::ScalarField>),
}

/// Proves ZK { ({Uⱼ, Gᵢⱼ, Hⱼ}; {wᵢ}_{i=0}^{t-1}, {xⱼ}_{j=1}^k) : ∧ Uⱼ = xⱼHⱼ + Σ wᵢGᵢⱼ }. Uses the
/// context provided by `transcript` to create the ZK challenge.
///
/// Panics
/// ======
/// Panics if the relation does not hold wrt the given values.
pub(crate) fn prove_multi_dleq<G, R>(
    rng: &mut R,
    transcript: &mut Transcript,
    uu: &[G],
    ggg: &Vec<Vec<G>>,
    hh: &[G],
    ww: &[G::ScalarField],
    xx: &[G::ScalarField],
) -> MultiDleqProof<G>
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
    R: CryptoRng + Rng,
{
    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", DOMAIN_STR);

    // Make sure all the inputs are the same size
    let k = uu.len();
    assert_eq!(k, ggg.len());
    assert_eq!(k, hh.len());
    assert_eq!(k, xx.len());

    // Make sure the number of w's matches the number g's in each gg
    let t = ww.len();
    for gg in ggg {
        assert_eq!(t, gg.len());
    }

    transcript.append_u64(b"k", k as u64);
    transcript.append_u64(b"t", t as u64);

    // Make sure the statement is true
    for (u, (gg, (h, x))) in uu.iter().zip(ggg.iter().zip(hh.iter().zip(xx.iter()))) {
        assert_eq!(u, &(dot_prod(ww, gg) + h.mul(x)));
    }

    // Pick random r, {sⱼ}
    let rr: Vec<_> = core::iter::repeat_with(|| G::ScalarField::rand(rng))
        .take(t)
        .collect();
    let ss: Vec<_> = core::iter::repeat_with(|| G::ScalarField::rand(rng))
        .take(k)
        .collect();
    // Construct commitments comⱼ = rGⱼ + sⱼHⱼ
    let coms = ss
        .iter()
        .zip(ggg.iter().zip(hh.iter()))
        .map(|(s, (gg, h))| dot_prod(&rr, gg) + h.mul(s))
        .collect();

    // Update the transcript
    transcript.append_serializable(b"uu", uu);
    transcript.append_serializable(b"ggg", ggg);
    transcript.append_serializable(b"hh", hh);
    transcript.append_serializable(b"coms", &coms);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Respond with rᵢ' = rᵢ - cwᵢ and sⱼ' = sⱼ - cxⱼ
    let rps = rr.iter().zip(ww.iter()).map(|(&r, w)| r - c * w).collect();
    let sps = ss.iter().zip(xx.iter()).map(|(&s, x)| s - c * x).collect();

    MultiDleqProof {
        coms,
        resp: (rps, sps),
    }
}

/// Verifies ZK { ({Uⱼ, Gᵢⱼ, Hⱼ}; {wᵢ}_{i=0}^{t-1}, {xⱼ}_{j=1}^k) : ∧ Uⱼ = xⱼHⱼ + Σ wᵢGᵢⱼ }. Uses
/// the context provided by the context provided by `transcript` to create the ZK challenge.
#[must_use]
pub(crate) fn verify_multi_dleq<G>(
    transcript: &mut Transcript,
    proof: &MultiDleqProof<G>,
    uu: &[G],
    ggg: &Vec<Vec<G>>,
    hh: &[G],
) -> bool
where
    G: Group + CanonicalSerialize + CanonicalDeserialize,
{
    let (rps, sps) = &proof.resp;

    // Domain-separate this protocol
    transcript.append_message(b"dom-sep", DOMAIN_STR);

    // Make sure all the inputs are the same size
    let k = uu.len();
    assert_eq!(k, ggg.len());
    assert_eq!(k, hh.len());

    // Make sure the number of w's matches the number g's in each gg
    let t = rps.len();
    for gg in ggg {
        assert_eq!(t, gg.len());
    }

    transcript.append_u64(b"k", k as u64);
    transcript.append_u64(b"t", t as u64);

    let coms = &proof.coms;

    // Update the transcript
    transcript.append_serializable(b"uu", uu);
    transcript.append_serializable(b"ggg", ggg);
    transcript.append_serializable(b"hh", hh);
    transcript.append_serializable(b"coms", coms);

    // Get a challenge from the transcript hash
    let c: G::ScalarField = transcript.challenge_scalar(b"c");

    // Check that comⱼ ==  sⱼHⱼ + cUⱼ + Σ r'ᵢGᵢⱼ
    coms.iter()
        .zip(sps.iter().zip(ggg.iter().zip(hh.iter().zip(uu.iter()))))
        .all(|(&com, (s, (gg, (h, u))))| com == dot_prod(rps, gg) + h.mul(s) + u.mul(&c))
}

#[test]
fn test_multi_dleq_correctness() {
    use ark_ec::PairingEngine;

    type F = <G as Group>::ScalarField;
    type G = <ark_bls12_381::Bls12_381 as PairingEngine>::G1Projective;

    const K: usize = 10;
    const T: usize = 3;

    // Pick the public elements
    let mut rng = ark_std::test_rng();
    let ggg: Vec<_> = core::iter::repeat_with(|| {
        core::iter::repeat_with(|| G::rand(&mut rng))
            .take(T)
            .collect::<Vec<G>>()
    })
    .take(K)
    .collect();
    let hh: Vec<_> = core::iter::repeat_with(|| G::rand(&mut rng))
        .take(K)
        .collect();

    // Pick the witnesses
    let ww: Vec<_> = core::iter::repeat_with(|| F::rand(&mut rng))
        .take(T)
        .collect();
    let xx: Vec<_> = core::iter::repeat_with(|| F::rand(&mut rng))
        .take(K)
        .collect();

    // Compute the curve points using the witnesses
    let uu: Vec<_> = ggg
        .iter()
        .zip(hh.iter().zip(xx.iter()))
        .map(|(gg, (h, x))| dot_prod(&ww, gg) + h.mul(x))
        .collect();

    // Make an empty transcript for proving, and prove the relation
    let mut proving_transcript = Transcript::new(b"test_multi_dleq_correctness");
    let proof = prove_multi_dleq(&mut rng, &mut proving_transcript, &uu, &ggg, &hh, &ww, &xx);

    // Now make an empty transcript for verifying, and verify the relation
    let mut verifying_transcript = Transcript::new(b"test_multi_dleq_correctness");
    assert!(verify_multi_dleq(
        &mut verifying_transcript,
        &proof,
        &uu,
        &ggg,
        &hh,
    ));
}
