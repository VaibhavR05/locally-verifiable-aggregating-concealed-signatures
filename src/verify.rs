use crate::keys::VerifyKey;
use crate::params::{G1, G2};
use crate::setup::CSetupParameters;
use crate::signature::Signature;
use crate::types::{AggregateSignature, ConcealedSignature, LocalAggregateOpening};
use crate::utils::hash_to_g1;

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, CurveGroup, hashing::HashToCurveError, pairing::Pairing};

// Verification function for the base BLS signature scheme.
pub fn verify(
    vk: &VerifyKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, HashToCurveError> {
    let h: G1 = hash_to_g1(message)?;
    let pairing_left = Bls12_381::pairing(signature.value, G2::generator());
    let pairing_right = Bls12_381::pairing(h, vk.value);

    Ok(pairing_left == pairing_right)
}

pub fn verify_concealed(
    concealed_signature: &ConcealedSignature,
    verify_key: &VerifyKey,
    cs_params: &CSetupParameters,
) -> bool {
    let v1 = cs_params.v.v1;
    let v2 = cs_params.v.v2;
    let w1 = cs_params.w.w1;
    let w2 = cs_params.w.w2;

    let g2 = G2::generator();
    let vk = verify_key.value;

    let lhs1 = Bls12_381::multi_pairing(
        [
            concealed_signature.signature_commitment.c1,
            concealed_signature.message_commitment.c1,
        ],
        [g2, -vk],
    );

    let rhs1 = Bls12_381::multi_pairing(
        [v1, w1],
        [concealed_signature.proof.z1, concealed_signature.proof.z2],
    );

    let lhs2 = Bls12_381::multi_pairing(
        [
            concealed_signature.signature_commitment.c2,
            concealed_signature.message_commitment.c2,
        ],
        [g2, -vk],
    );

    let rhs2 = Bls12_381::multi_pairing(
        [v2, w2],
        [concealed_signature.proof.z1, concealed_signature.proof.z2],
    );

    (lhs1 == rhs1) && (lhs2 == rhs2)
}

pub fn verify_aggregate(
    verify_key_list: &[VerifyKey],
    aggregate_signature: &AggregateSignature,
    cs_params: &CSetupParameters,
) -> bool {
    let avk = verify_key_list
        .iter()
        .map(|verify_key| verify_key.value)
        .reduce(|a, b| (a + b).into_affine())
        .expect("empty verify key list");

    assert_eq!(
        avk, aggregate_signature.avk,
        "Verification Key List is not valid"
    );

    let v1 = cs_params.v.v1;
    let v2 = cs_params.v.v2;
    let w1 = cs_params.w.w1;
    let w2 = cs_params.w.w2;

    let g2 = G2::generator();

    let lhs1 = Bls12_381::multi_pairing(
        [
            aggregate_signature.signature_commitment.c1,
            aggregate_signature.message_commitment.c1,
        ],
        [g2, -avk],
    ) + aggregate_signature.cross.t1;

    let rhs1 = Bls12_381::multi_pairing(
        [v1, w1],
        [aggregate_signature.proof.z1, aggregate_signature.proof.z2],
    );

    let lhs2 = Bls12_381::multi_pairing(
        [
            aggregate_signature.signature_commitment.c2,
            aggregate_signature.message_commitment.c2,
        ],
        [g2, -avk],
    ) + aggregate_signature.cross.t2;

    let rhs2 = Bls12_381::multi_pairing(
        [v2, w2],
        [aggregate_signature.proof.z1, aggregate_signature.proof.z2],
    );

    (lhs1 == rhs1) && (lhs2 == rhs2)
}

pub fn local_verify(
    verify_key: &VerifyKey,
    aggregate_signature: &AggregateSignature,
    local_opening: &LocalAggregateOpening,
    concealed_signature: &ConcealedSignature,
    cs_params: &CSetupParameters,
) -> bool {
    let g2 = G2::generator();

    let v1 = cs_params.v.v1;
    let v2 = cs_params.v.v2;
    let w1 = cs_params.w.w1;
    let w2 = cs_params.w.w2;

    let sig_commit_bind = aggregate_signature.signature_commitment
        == concealed_signature.signature_commitment.clone()
            + local_opening.signature_commitment.clone();
    let msg_commit_bind = aggregate_signature.message_commitment
        == concealed_signature.message_commitment.clone()
            + local_opening.message_commitment.clone();
    let proof_bind = aggregate_signature.proof
        == concealed_signature.proof.clone() + local_opening.proof.clone();

    let lhs1 = Bls12_381::multi_pairing(
        [
            local_opening.signature_commitment.c1,
            local_opening.message_commitment.c1,
            concealed_signature.signature_commitment.c1,
            concealed_signature.message_commitment.c1,
        ],
        [g2, -aggregate_signature.avk, g2, -verify_key.value],
    ) + local_opening.cross.t1;

    let rhs1 = Bls12_381::multi_pairing(
        [v1, w1, v1, w1],
        [
            local_opening.proof.z1,
            local_opening.proof.z2,
            concealed_signature.proof.z1,
            concealed_signature.proof.z2,
        ],
    );

    let lhs2 = Bls12_381::multi_pairing(
        [
            local_opening.signature_commitment.c2,
            local_opening.message_commitment.c2,
            concealed_signature.signature_commitment.c2,
            concealed_signature.message_commitment.c2,
        ],
        [g2, -aggregate_signature.avk, g2, -verify_key.value],
    ) + local_opening.cross.t2;

    let rhs2 = Bls12_381::multi_pairing(
        [v2, w2, v2, w2],
        [
            local_opening.proof.z1,
            local_opening.proof.z2,
            concealed_signature.proof.z1,
            concealed_signature.proof.z2,
        ],
    );

    msg_commit_bind && sig_commit_bind && proof_bind && (lhs1 == rhs1) && (lhs2 == rhs2)
}
