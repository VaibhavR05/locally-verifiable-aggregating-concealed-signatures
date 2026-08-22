use crate::keys::VerifyKey;
use crate::params::{G1, G2};
use crate::signature::Signature;
use crate::utils::hash_to_g1;

use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr};

// Verification function for the base BLS signature scheme.
pub fn verify(
    vk: &VerifyKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, ark_ec::hashing::HashToCurveError> {
    let h: G1 = hash_to_g1(message)?;
    let pairing_left = Bls12_381::pairing(signature.value, G2::generator());
    let pairing_right = Bls12_381::pairing(h, vk.value);
    Ok(pairing_left == pairing_right)
}