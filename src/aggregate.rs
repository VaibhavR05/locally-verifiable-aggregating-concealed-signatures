use crate::keys::VerifyKey;
use crate::types::{AggregateSignature, ConcealedSignature, Cross};
use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, pairing::Pairing};

pub fn aggregate_concealed_signatures(
    verify_key_list: &[VerifyKey],
    signature_list: &[ConcealedSignature],
) -> AggregateSignature {
    assert_eq!(
        verify_key_list.len(),
        signature_list.len(),
        "verification key and signature list lengths differ"
    );

    // Get the aggregated public key avk
    let avk = verify_key_list
        .iter()
        .map(|verify_key| verify_key.value)
        .reduce(|a, b| (a + b).into_affine())
        .expect("empty verify key list");

    // Aggregate all other terms in one loop
    let (agg_sig, agg_msg, agg_proof, agg_cross) = signature_list
        .iter()
        .zip(verify_key_list.iter())
        .map(|(signature, verify_key)| {
            let cross = Cross {
                t1: Bls12_381::pairing(
                    signature.message_commitment.c1,
                    (avk - verify_key.value).into_affine(),
                ),
                t2: Bls12_381::pairing(
                    signature.message_commitment.c2,
                    (avk - verify_key.value).into_affine(),
                ),
            };
            (
                signature.signature_commitment.clone(),
                signature.message_commitment.clone(),
                signature.proof.clone(),
                cross,
            )
        })
        .reduce(
            |(sig_a, msg_a, proof_a, cross_a), (sig_b, msg_b, proof_b, cross_b)| {
                (
                    sig_a + sig_b,
                    msg_a + msg_b,
                    proof_a + proof_b,
                    cross_a + cross_b,
                )
            },
        )
        .expect("empty signature list");

    AggregateSignature {
        signature_commitment: agg_sig,
        message_commitment: agg_msg,
        proof: agg_proof,
        avk,
        cross: agg_cross,
    }
}
