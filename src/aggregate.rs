use crate::keys::VerifyKey;
use crate::types::{
    AggregateSignature, Commitment, ConcealedSignature, Cross, LocalAggregateOpening, Proof,
};
use ark_bls12_381::Bls12_381;
use ark_ec::AffineRepr;
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

    let avk = verify_key_list
        .iter()
        .map(|verify_key| verify_key.value)
        .reduce(|a, b| (a + b).into_affine())
        .expect("empty verify key list");

    let mut agg_sig_commitment = Commitment {
        c1: ark_bls12_381::G1Affine::zero(),
        c2: ark_bls12_381::G1Affine::zero(),
    };
    let mut agg_msg_commitment = Commitment {
        c1: ark_bls12_381::G1Affine::zero(),
        c2: ark_bls12_381::G1Affine::zero(),
    };
    let mut agg_proof = Proof {
        z1: ark_bls12_381::G2Affine::zero(),
        z2: ark_bls12_381::G2Affine::zero(),
    };

    // Collect every (G1, G2) pair instead of pairing (Miller loop + final
    // exponentiation) per signer; one multi_pairing at the end does a single
    // combined Miller loop + single final exponentiation for the whole batch.
    let mut t1_lhs = Vec::with_capacity(signature_list.len());
    let mut t1_rhs = Vec::with_capacity(signature_list.len());
    let mut t2_lhs = Vec::with_capacity(signature_list.len());
    let mut t2_rhs = Vec::with_capacity(signature_list.len());

    for (verify_key, concealed_signature) in verify_key_list.iter().zip(signature_list.iter()) {
        agg_msg_commitment = agg_msg_commitment + concealed_signature.message_commitment.clone();
        agg_sig_commitment = agg_sig_commitment + concealed_signature.signature_commitment.clone();
        agg_proof = agg_proof + concealed_signature.proof.clone();

        let diff = (avk - verify_key.value).into_affine();
        t1_lhs.push(concealed_signature.message_commitment.c1);
        t1_rhs.push(diff);
        t2_lhs.push(concealed_signature.message_commitment.c2);
        t2_rhs.push(diff);
    }

    let agg_cross = Cross {
        t1: Bls12_381::multi_pairing(t1_lhs, t1_rhs),
        t2: Bls12_381::multi_pairing(t2_lhs, t2_rhs),
    };

    AggregateSignature {
        signature_commitment: agg_sig_commitment,
        message_commitment: agg_msg_commitment,
        proof: agg_proof,
        avk,
        cross: agg_cross,
    }
}

pub fn local_aggregate_opening(
    aggregate_signature: &AggregateSignature,
    verify_key_list: &[VerifyKey],
    signature_list: &[ConcealedSignature],
    index: usize,
) -> LocalAggregateOpening {
    assert_eq!(
        verify_key_list.len(),
        signature_list.len(),
        "verification key and signature list lengths differ"
    );
    assert!(
        index < signature_list.len(),
        "local opening index out of bounds"
    );

    let mut local_signature_commitment = Commitment {
        c1: ark_bls12_381::G1Affine::zero(),
        c2: ark_bls12_381::G1Affine::zero(),
    };
    let mut local_message_commitment = Commitment {
        c1: ark_bls12_381::G1Affine::zero(),
        c2: ark_bls12_381::G1Affine::zero(),
    };
    let mut local_proof = Proof {
        z1: ark_bls12_381::G2Affine::zero(),
        z2: ark_bls12_381::G2Affine::zero(),
    };

    let mut t1_lhs = Vec::with_capacity(signature_list.len() - 1);
    let mut t1_rhs = Vec::with_capacity(signature_list.len() - 1);
    let mut t2_lhs = Vec::with_capacity(signature_list.len() - 1);
    let mut t2_rhs = Vec::with_capacity(signature_list.len() - 1);

    for (item_index, (verify_key, concealed_signature)) in verify_key_list
        .iter()
        .zip(signature_list.iter())
        .enumerate()
    {
        if item_index == index {
            continue;
        }

        local_signature_commitment =
            local_signature_commitment + concealed_signature.signature_commitment.clone();
        local_message_commitment =
            local_message_commitment + concealed_signature.message_commitment.clone();
        local_proof = local_proof + concealed_signature.proof.clone();

        let diff = (aggregate_signature.avk - verify_key.value).into_affine();
        t1_lhs.push(concealed_signature.message_commitment.c1);
        t1_rhs.push(diff);
        t2_lhs.push(concealed_signature.message_commitment.c2);
        t2_rhs.push(diff);
    }

    let local_cross = Cross {
        t1: Bls12_381::multi_pairing(t1_lhs, t1_rhs),
        t2: Bls12_381::multi_pairing(t2_lhs, t2_rhs),
    };

    LocalAggregateOpening {
        signature_commitment: local_signature_commitment,
        message_commitment: local_message_commitment,
        proof: local_proof,
        cross: local_cross,
    }
}