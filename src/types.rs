use crate::params::{F, G1, G2};

use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, pairing::PairingOutput};

// Standard format for both signature and message commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub(crate) c1: G1,
    pub(crate) c2: G1,
}

// Proof of knowledge elements belong to G2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub(crate) z1: G2,
    pub(crate) z2: G2,
}

// Structure of our concealed signature, which includes commitments and a proof of knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcealedSignature {
    pub(crate) signature_commitment: Commitment,
    pub(crate) message_commitment: Commitment,
    pub(crate) proof: Proof,
}

// Our auxilary data which will be helpful for opening the concealed signature.
pub struct AuxiliaryData {
    pub(crate) r_sig: F,
    pub(crate) s_sig: F,
    pub(crate) r_msg: F,
    pub(crate) s_msg: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cross {
    pub(crate) t1: PairingOutput<Bls12_381>,
    pub(crate) t2: PairingOutput<Bls12_381>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateSignature {
    pub(crate) signature_commitment: Commitment,
    pub(crate) message_commitment: Commitment,
    pub(crate) proof: Proof,
    pub(crate) avk: G2,
    pub(crate) cross: Cross,
}

// Custom implementation of addition to simplify aggregation
impl std::ops::Add for Commitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            c1: (self.c1 + other.c1).into_affine(),
            c2: (self.c2 + other.c2).into_affine(),
        }
    }
}

impl std::ops::Add for Proof {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            z1: (self.z1 + other.z1).into_affine(),
            z2: (self.z2 + other.z2).into_affine(),
        }
    }
}

impl std::ops::Add for Cross {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self {
            t1: self.t1 + &other.t1,
            t2: self.t2 + &other.t2,
        }
    }
}
