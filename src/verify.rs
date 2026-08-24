use crate::keys::VerifyKey;
use crate::params::{G1, G2};
use crate::setup::CSetupParameters;
use crate::signature::Signature;
use crate::types::{AggregateSignature, ConcealedSignature, LocalAggregateOpening};
use crate::utils::hash_to_g1;

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, CurveGroup, hashing::HashToCurveError, pairing::Pairing};
use ark_ff::Zero;

pub fn verify(
    vk: &VerifyKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, HashToCurveError> {
    let h: G1 = hash_to_g1(message)?;

    // e(sig, g2) == e(h, vk)  <=>  e(sig, g2) * e(h, -vk) == 1
    let check = Bls12_381::multi_pairing([signature.value, h], [G2::generator(), -vk.value]);

    Ok(check.is_zero())
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
    let z1 = concealed_signature.proof.z1;
    let z2 = concealed_signature.proof.z2;

    let check1 = Bls12_381::multi_pairing(
        [
            concealed_signature.signature_commitment.c1,
            concealed_signature.message_commitment.c1,
            v1,
            w1,
        ],
        [g2, -vk, -z1, -z2],
    );

    let check2 = Bls12_381::multi_pairing(
        [
            concealed_signature.signature_commitment.c2,
            concealed_signature.message_commitment.c2,
            v2,
            w2,
        ],
        [g2, -vk, -z1, -z2],
    );

    check1.is_zero() && check2.is_zero()
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
    let z1 = aggregate_signature.proof.z1;
    let z2 = aggregate_signature.proof.z2;

    let check1 = Bls12_381::multi_pairing(
        [
            aggregate_signature.signature_commitment.c1,
            aggregate_signature.message_commitment.c1,
            v1,
            w1,
        ],
        [g2, -avk, -z1, -z2],
    ) + aggregate_signature.cross.t1;

    let check2 = Bls12_381::multi_pairing(
        [
            aggregate_signature.signature_commitment.c2,
            aggregate_signature.message_commitment.c2,
            v2,
            w2,
        ],
        [g2, -avk, -z1, -z2],
    ) + aggregate_signature.cross.t2;

    check1.is_zero() && check2.is_zero()
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

    let lo_z1 = local_opening.proof.z1;
    let lo_z2 = local_opening.proof.z2;
    let cs_z1 = concealed_signature.proof.z1;
    let cs_z2 = concealed_signature.proof.z2;

    let check1 = Bls12_381::multi_pairing(
        [
            local_opening.signature_commitment.c1,
            local_opening.message_commitment.c1,
            concealed_signature.signature_commitment.c1,
            concealed_signature.message_commitment.c1,
            v1,
            w1,
            v1,
            w1,
        ],
        [
            g2,
            -aggregate_signature.avk,
            g2,
            -verify_key.value,
            -lo_z1,
            -lo_z2,
            -cs_z1,
            -cs_z2,
        ],
    ) + local_opening.cross.t1;

    let check2 = Bls12_381::multi_pairing(
        [
            local_opening.signature_commitment.c2,
            local_opening.message_commitment.c2,
            concealed_signature.signature_commitment.c2,
            concealed_signature.message_commitment.c2,
            v2,
            w2,
            v2,
            w2,
        ],
        [
            g2,
            -aggregate_signature.avk,
            g2,
            -verify_key.value,
            -lo_z1,
            -lo_z2,
            -cs_z1,
            -cs_z2,
        ],
    ) + local_opening.cross.t2;

    msg_commit_bind && sig_commit_bind && proof_bind && check1.is_zero() && check2.is_zero()
}