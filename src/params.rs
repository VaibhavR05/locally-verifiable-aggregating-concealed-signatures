use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;

pub type F = Fr;

// Projective is better suited for computations, return here if we need to change
pub type G1 = <Bls12_381 as Pairing>::G1Affine;
pub type G2 = <Bls12_381 as Pairing>::G2Affine;

pub type Gt = <Bls12_381 as Pairing>::TargetField;

pub const P: u64 = 1u64 << 63;