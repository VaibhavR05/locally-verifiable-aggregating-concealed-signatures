use ark_ec::CurveGroup;
use std::ops::Mul;

use crate::keys::SignKey;
use crate::params::G1;
use crate::utils::hash_to_g1;

// Base BLS signature scheme implementation. 
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) value: G1,
}

pub fn sign(
    sk: &SignKey,
    message: &[u8],
) -> Result<Signature, ark_ec::hashing::HashToCurveError> {
    let h = hash_to_g1(message)?;
    let sig = h.mul(sk.value).into_affine();
    Ok(Signature { value: sig })
}