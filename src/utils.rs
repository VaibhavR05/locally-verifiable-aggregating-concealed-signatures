use ark_bls12_381::{g1::Config as G1Config, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve,
    HashToCurveError,
};
use ark_ff::{field_hashers::DefaultFieldHasher, UniformRand, Zero};
use ark_std::rand::Rng;
use sha2::Sha256;

use crate::params::G1;

// Using SHA256 for now, will probably need to switch later on
const G1_HASH_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Sampling for x (secret key) and a (in csetup) require Zp* instead of Zp
pub fn sample_nonzero<F, R>(rng: &mut R) -> F
where
    F: UniformRand + Zero,
    R: Rng,
{
    loop {
        let value = F::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

pub fn hash_to_g1(message: &[u8]) -> Result<G1, HashToCurveError> {
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G1Config>,
    >::new(G1_HASH_DST)?;

    hasher.hash(message)
}
