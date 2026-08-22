use crate::params::{F, G2};
use crate::utils::sample_nonzero;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::Rng;

// Simple implementation for the keys required for the base signature scheme (BLS in our case).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyKey {
    pub(crate) value: G2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignKey {
    pub(crate) value: F,
}

// Standard key generation for BLS signatures.
pub fn key_gen<R: Rng>(rng: &mut R) -> (SignKey, VerifyKey) {
    let x = sample_nonzero::<F, R>(rng);
    let sk = SignKey { value: x };
    let vk = VerifyKey {
        value: (G2::generator() * sk.value).into_affine(),
    };
    (sk, vk)
}
