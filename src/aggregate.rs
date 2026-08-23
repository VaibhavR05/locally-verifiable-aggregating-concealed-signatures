use crate::keys::VerifyKey;
use crate::types::{
    AggregateSignature, Commitment, ConcealedSignature, Cross, LocalAggregateOpening, Proof,
};
use ark_bls12_381::Bls12_381;
use ark_ec::AffineRepr;
use ark_ec::pairing::PairingOutput;
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::Zero;

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
    let mut agg_cross = Cross {
        t1: PairingOutput::<Bls12_381>::zero(),
        t2: PairingOutput::<Bls12_381>::zero(),
    };

    for (verify_key, concealed_signature) in verify_key_list.iter().zip(signature_list.iter()) {
        agg_msg_commitment = agg_msg_commitment + concealed_signature.message_commitment.clone();
        agg_sig_commitment = agg_sig_commitment + concealed_signature.signature_commitment.clone();
        agg_proof = agg_proof + concealed_signature.proof.clone();

        let cross = Cross {
            t1: Bls12_381::pairing(
                concealed_signature.message_commitment.c1,
                avk - verify_key.value,
            ),
            t2: Bls12_381::pairing(
                concealed_signature.message_commitment.c2,
                avk - verify_key.value,
            ),
        };

        agg_cross = agg_cross + cross;
    }

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

    // let mut local_signature_commitment = 
    //     aggregate_signature.signature_commitment.clone() - signature_list[index].signature_commitment.clone();
    
    // let mut local_message_commitment = 
    //     aggregate_signature.message_commitment.clone() - signature_list[index].message_commitment.clone();
    // let mut local_proof = 
    //     aggregate_signature.proof.clone() - signature_list[index].proof.clone();
    // // 
    
    // let cross = Cross {
    //         t1: Bls12_381::pairing(
    //             signature_list[index].message_commitment.c1,
    //             (aggregate_signature.avk - verify_key_list[index].value).into_affine(),
    //         ),
    //         t2: Bls12_381::pairing(
    //             signature_list[index].message_commitment.c2,
    //             (aggregate_signature.avk - verify_key_list[index].value).into_affine(),
    //         ),
    //     };

    // let mut local_cross = aggregate_signature.cross.clone() - cross.clone();


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
    let mut local_cross = Cross {
        t1: PairingOutput::<Bls12_381>::zero(),
        t2: PairingOutput::<Bls12_381>::zero(),
    };

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

        let cross = Cross {
            t1: Bls12_381::pairing(
                concealed_signature.message_commitment.c1,
                (aggregate_signature.avk - verify_key.value).into_affine(),
            ),
            t2: Bls12_381::pairing(
                concealed_signature.message_commitment.c2,
                (aggregate_signature.avk - verify_key.value).into_affine(),
            ),
        };
        local_cross = local_cross + cross;
    }

    LocalAggregateOpening {
        signature_commitment: local_signature_commitment,
        message_commitment: local_message_commitment,
        proof: local_proof,
        cross: local_cross,
    }
}
