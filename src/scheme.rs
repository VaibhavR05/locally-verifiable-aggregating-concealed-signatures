use crate::keys::{key_gen, SignKey, VerifyKey};
use crate::setup::{csetup, CSetupParameters};
use crate::signature::{sign, Signature};
use crate::verify::verify;
use ark_std::rand::Rng;

// Top level wrapper for the signature scheme, providing a clean interface for users.
pub struct Scheme;

impl Scheme {
	pub fn new() -> Self {
		Self
	}

	pub fn setup<R: Rng>(&self, rng: &mut R) -> CSetupParameters {
		csetup(rng)
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
}
