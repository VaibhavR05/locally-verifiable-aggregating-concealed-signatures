use crate::params::{F, G1};
use crate::utils::sample_nonzero;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

// V = (v_1, v_2) = (g^a, g)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V {
    pub v1: G1,
    pub v2: G1,
}

// W = (w_1, w_2) = (g^(ab), g^b)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct W {
    pub w1: G1,
    pub w2: G1,
}

// CSetupParameters = (V, W)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSetupParameters {
    pub v: V,
    pub w: W,
}

// Sample a and b to generate the concealed setup parameters (V, W)
pub fn csetup<R: Rng>(rng: &mut R) -> CSetupParameters {
    let a = sample_nonzero::<F, _>(rng);
    let b = F::rand(rng);
    let g = G1::generator();

    let ga = (g * a).into_affine();
    let gb = (g * b).into_affine();
    let gab = (ga * b).into_affine();

    CSetupParameters {
        v: V { v1: ga, v2: g },
        w: W { w1: gab, w2: gb },
    }
}