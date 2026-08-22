use crate::keys::VerifyKey;
use crate::params::{F, G2};
use crate::setup::CSetupParameters;
use crate::types::{AuxiliaryData, Commitment, ConcealedSignature, Proof};
use crate::utils::hash_to_g1;

use ark_ec::{AffineRepr, CurveGroup, hashing::HashToCurveError};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

pub fn convert<R: Rng>(
    cs_params: &CSetupParameters,
    verify_key: &VerifyKey,
    message: &[u8],
    signature: &crate::signature::Signature,
    rng: &mut R,
) -> Result<(ConcealedSignature, AuxiliaryData), HashToCurveError> {
    // The necessary elements from the concealed setup parameters
    let v1 = cs_params.v.v1;
    let v2 = cs_params.v.v2;
    let w1 = cs_params.w.w1;
    let w2 = cs_params.w.w2;

    // The randomness sampled to generate the commitments and proof of knowledge
    let r_sig = F::rand(rng);
    let s_sig = F::rand(rng);
    let r_msg = F::rand(rng);
    let s_msg = F::rand(rng);

    let g2 = G2::generator();
    let vk = verify_key.value;

    let signature_commitment = Commitment {
        c1: (v1 * r_sig + w1 * s_sig).into_affine(),
        c2: (signature.value + v2 * r_sig + w2 * s_sig).into_affine(),
    };

    let message_commitment = Commitment {
        c1: (v1 * r_msg + w1 * s_msg).into_affine(),
        c2: (hash_to_g1(message)? + v2 * r_msg + w2 * s_msg).into_affine(),
    };

    let proof = Proof {
        z1: (g2 * r_sig - vk * r_msg).into_affine(),
        z2: (g2 * s_sig - vk * s_msg).into_affine(),
    };

    let concealed_signature = ConcealedSignature {
        signature_commitment,
        message_commitment,
        proof,
    };

    let aux_data = AuxiliaryData {
        r_sig,
        s_sig,
        r_msg,
        s_msg,
    };

    Ok((concealed_signature, aux_data))
}
