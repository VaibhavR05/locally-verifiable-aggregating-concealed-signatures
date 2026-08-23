use crate::setup::CSetupParameters;
// use crate::signature::Signature;
use crate::types::{AuxiliaryData, Commitment, ConcealedSignature};
use crate::utils::hash_to_g1;

use ark_ec::CurveGroup;
use ark_ec::hashing::HashToCurveError;

pub fn open_concealed_signature(
    message: &[u8],
    // signature: &Signature,
    concealed_sig: &ConcealedSignature,
    aux: &AuxiliaryData,
    cs_params: &CSetupParameters,
) -> Result<bool, HashToCurveError> {
    let v1 = cs_params.v.v1;
    let v2 = cs_params.v.v2;
    let w1 = cs_params.w.w1;
    let w2 = cs_params.w.w2;

    let derived_message_commitment = Commitment {
        c1: (v1 * aux.r_msg + w1 * aux.s_msg).into_affine(),
        c2: (hash_to_g1(message)? + v2 * aux.r_msg + w2 * aux.s_msg).into_affine(),
    };

    // let derived_sign_commitment = Commitment {
    //     c1: (v1 * aux.r_sig + w1 * aux.s_sig).into_affine(),
    //     c2: (signature.value + v2 * aux.r_sig + w2 * aux.s_sig).into_affine()
    // };

    // Ok(derived_message_commitment == concealed_sig.message_commitment &&
    // derived_sign_commitment == concealed_sig.signature_commitment)
    Ok(derived_message_commitment == concealed_sig.message_commitment)
}
