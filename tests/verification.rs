use ark_std::test_rng;
use lvacs::{keys::key_gen, signature::sign, verify::verify};

// TESTS FOR THE BASE SIGNATURE SCHEME (BLS)

#[test]
// Valid signature should verify successfully
fn valid_signature() {
	let mut rng = test_rng();
	let (signing_key, verification_key) = key_gen(&mut rng);
	let message = b"base signing test";
	let signature = sign(&signing_key, message).expect("hashing should succeed");

	assert!(
		verify(&verification_key, message, &signature)
			.expect("verification hashing should succeed")
	);
}

#[test]
// Signature should not verify with a different message
fn wrong_message() {
	let mut rng = test_rng();
	let (signing_key, verification_key) = key_gen(&mut rng);
	let signature = sign(&signing_key, b"original message").expect("hashing should succeed");

	assert!(!verify(&verification_key, b"different message", &signature)
		.expect("verification hashing should succeed"));
}

#[test]
// Signature should not verify with a different key
fn wrong_key() {
	let mut rng = test_rng();
	let (signing_key, _) = key_gen(&mut rng);
	let (_, different_verification_key) = key_gen(&mut rng);
	let message = b"base signing test";
	let signature = sign(&signing_key, message).expect("hashing should succeed");

	assert!(!verify(&different_verification_key, message, &signature)
		.expect("verification hashing should succeed"));
}

#[test]
// Signing same input should produce the same signature
fn deterministic_signing() {
	let mut rng = test_rng();
	let (signing_key, verification_key) = key_gen(&mut rng);
	let message = b"deterministic signature";
	let first_signature = sign(&signing_key, message).expect("hashing should succeed");
	let second_signature = sign(&signing_key, message).expect("hashing should succeed");

	assert_eq!(first_signature, second_signature);
	assert!(verify(&verification_key, message, &first_signature)
		.expect("verification hashing should succeed"));
}
