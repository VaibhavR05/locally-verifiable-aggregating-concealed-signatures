use crate::conceal::ConcealedSignature;
use crate::keys::VerifyKey;
use crate::params::{G1, G2};
use crate::setup::CSetupParameters;
use crate::signature::Signature;
use crate::utils::hash_to_g1;

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, hashing::HashToCurveError, pairing::Pairing};

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
