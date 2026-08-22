use ark_std::test_rng;
use lvacs::{Scheme, key_gen, sign, verify};

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

    assert!(
        !verify(&verification_key, b"different message", &signature)
            .expect("verification hashing should succeed")
    );
}

#[test]
// Signature should not verify with a different key
fn wrong_key() {
    let mut rng = test_rng();
    let (signing_key, _) = key_gen(&mut rng);
    let (_, different_verification_key) = key_gen(&mut rng);
    let message = b"base signing test";
    let signature = sign(&signing_key, message).expect("hashing should succeed");

    assert!(
        !verify(&different_verification_key, message, &signature)
            .expect("verification hashing should succeed")
    );
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
    assert!(
        verify(&verification_key, message, &first_signature)
            .expect("verification hashing should succeed")
    );
}

// TESTS FOR THE CONCEALED SIGNATURE SCHEME

#[test]
fn verify_and_open_cs() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let (signing_key, verification_key) = key_gen(&mut rng);
    let message = b"concealed signing test";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, auxiliary_data) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    assert!(scheme.verify_concealed(&concealed_signature, &verification_key,));
    assert!(
        scheme
            .open_concealed_signature(message, &concealed_signature, &auxiliary_data)
            .expect("hashing should succeed")
    );
}

#[test]
fn wrong_msg_open() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let (signing_key, verification_key) = key_gen(&mut rng);
    let message = b"original concealed message";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, auxiliary_data) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    assert!(
        !scheme
            .open_concealed_signature(
                b"different concealed message",
                &concealed_signature,
                &auxiliary_data,
            )
            .expect("hashing should succeed")
    );
}

#[test]
fn wrong_param_open() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let different_scheme = Scheme::new(&mut rng);
    let (signing_key, verification_key) = key_gen(&mut rng);
    let message = b"setup binding test";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, _) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    assert!(!different_scheme.verify_concealed(&concealed_signature, &verification_key));
}

#[test]
fn wrong_key_verify() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let (signing_key, _) = key_gen(&mut rng);
    let (_, verification_key) = key_gen(&mut rng);
    let message = b"wrong signing key test";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, _) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    assert!(!scheme.verify_concealed(&concealed_signature, &verification_key));
}
