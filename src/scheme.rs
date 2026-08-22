use crate::aggregate::aggregate_concealed_signatures;
use crate::conceal::convert;
use crate::keys::{SignKey, VerifyKey, key_gen};
use crate::open::open_concealed_signature;
use crate::setup::{CSetupParameters, csetup};
use crate::signature::{Signature, sign};
use crate::types::{AggregateSignature, AuxiliaryData, ConcealedSignature};
use crate::verify::{verify, verify_aggregate, verify_concealed};

use ark_std::rand::Rng;

// Top level wrapper for the signature scheme, providing a clean interface for users.
pub struct Scheme {
    cs_params: CSetupParameters,
}

impl Scheme {
    // Slightly modified the constructor to automatically set up params at initialization.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            cs_params: csetup(rng),
        }
    }

    pub fn key_gen<R: Rng>(&self, rng: &mut R) -> (SignKey, VerifyKey) {
        key_gen(rng)
    }

    pub fn sign(
        &self,
        signing_key: &SignKey,
        message: &[u8],
    ) -> Result<Signature, ark_ec::hashing::HashToCurveError> {
        sign(signing_key, message)
    }

    pub fn verify(
        &self,
        verification_key: &VerifyKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, ark_ec::hashing::HashToCurveError> {
        verify(verification_key, message, signature)
    }

    pub fn convert<R: Rng>(
        &self,
        verification_key: &VerifyKey,
        message: &[u8],
        signature: &Signature,
        rng: &mut R,
    ) -> Result<(ConcealedSignature, AuxiliaryData), ark_ec::hashing::HashToCurveError> {
        convert(&self.cs_params, verification_key, message, signature, rng)
    }

    pub fn verify_concealed(
        &self,
        concealed_signature: &ConcealedSignature,
        verification_key: &VerifyKey,
    ) -> bool {
        verify_concealed(concealed_signature, verification_key, &self.cs_params)
    }

    pub fn open_concealed_signature(
        &self,
        message: &[u8],
        concealed_signature: &ConcealedSignature,
        auxiliary_data: &AuxiliaryData,
    ) -> Result<bool, ark_ec::hashing::HashToCurveError> {
        open_concealed_signature(
            message,
            concealed_signature,
            auxiliary_data,
            &self.cs_params,
        )
    }

    pub fn aggregate_concealed_signatures(
        &self,
        verify_key_list: &[VerifyKey],
        signature_list: &[ConcealedSignature],
    ) -> AggregateSignature {
        aggregate_concealed_signatures(verify_key_list, signature_list)
    }

    pub fn verify_aggregate(
        &self,
        verify_key_list: &[VerifyKey],
        aggregate_signature: &AggregateSignature,
    ) -> bool {
        verify_aggregate(verify_key_list, aggregate_signature, &self.cs_params)
    }
}
