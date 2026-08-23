use ark_std::rand::Rng;
use ark_std::test_rng;
use lvacs::{AggregateSignature, ConcealedSignature, Scheme, VerifyKey, key_gen, sign, verify};

fn generete_agg_tests<R: Rng>(
    rng: &mut R,
    messages: &[&[u8]],
) -> (
    Scheme,
    Vec<VerifyKey>,
    Vec<ConcealedSignature>,
    AggregateSignature,
) {
    let scheme = Scheme::new(rng);
    let mut verification_keys = Vec::with_capacity(messages.len());
    let mut concealed_signatures = Vec::with_capacity(messages.len());

    for message in messages {
        let (verification_key, signing_key) = key_gen(rng);
        let signature = sign(&signing_key, message).expect("hashing should succeed");
        let (concealed_signature, _) = scheme
            .convert(&verification_key, message, &signature, rng)
            .expect("hashing should succeed");

        verification_keys.push(verification_key);
        concealed_signatures.push(concealed_signature);
    }

    let aggregate =
        scheme.aggregate_concealed_signatures(&verification_keys, &concealed_signatures);

    (scheme, verification_keys, concealed_signatures, aggregate)
}

// TESTS FOR THE BASE SIGNATURE SCHEME (BLS)

#[test]
// Valid signature should verify successfully
fn valid_signature() {
    let mut rng = test_rng();
    let (verification_key, signing_key) = key_gen(&mut rng);
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
    let (verification_key, signing_key) = key_gen(&mut rng);
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
    let (_,signing_key) = key_gen(&mut rng);
    let (different_verification_key,_) = key_gen(&mut rng);
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
    let (verification_key, signing_key) = key_gen(&mut rng);
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
    let (verification_key, signing_key) = key_gen(&mut rng);
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
    let (verification_key, signing_key) = key_gen(&mut rng);
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
fn wrong_params_concealed() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let different_scheme = Scheme::new(&mut rng);
    let (verification_key, signing_key) = key_gen(&mut rng);
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
    let ( _,signing_key) = key_gen(&mut rng);
    let (verification_key, _) = key_gen(&mut rng);
    let message = b"wrong signing key test";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, _) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    assert!(!scheme.verify_concealed(&concealed_signature, &verification_key));
}

// TESTS FOR AGGREGATE SIGNATURES

#[test]
fn valid_aggregate() {
    let mut rng = test_rng();
    let messages: &[&[u8]] = &[b"aggregate message one", b"aggregate message two"];
    let (scheme, verification_keys, _, aggregate) = generete_agg_tests(&mut rng, messages);

    assert!(scheme.verify_aggregate(&verification_keys, &aggregate));
}

#[test]
fn wrong_key_aggregate() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let (_, wrong_signing_key) = key_gen(&mut rng);
    let (listed_verification_key, _) = key_gen(&mut rng);
    let message = b"aggregate member key binding";
    let signature = sign(&wrong_signing_key, message).expect("hashing should succeed");
    let (concealed_signature, _) = scheme
        .convert(&listed_verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    let aggregate = scheme.aggregate_concealed_signatures(
        std::slice::from_ref(&listed_verification_key),
        std::slice::from_ref(&concealed_signature),
    );

    assert!(!scheme.verify_aggregate(std::slice::from_ref(&listed_verification_key), &aggregate,));
}

#[test]
fn wrong_params_aggregate() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let different_scheme = Scheme::new(&mut rng);
    let (verification_key, signing_key) = key_gen(&mut rng);
    let message = b"aggregate setup binding";
    let signature = sign(&signing_key, message).expect("hashing should succeed");
    let (concealed_signature, _) = scheme
        .convert(&verification_key, message, &signature, &mut rng)
        .expect("hashing should succeed");

    let aggregate = scheme.aggregate_concealed_signatures(
        std::slice::from_ref(&verification_key),
        std::slice::from_ref(&concealed_signature),
    );

    assert!(
        !different_scheme.verify_aggregate(std::slice::from_ref(&verification_key), &aggregate,)
    );
}

#[test]
#[should_panic(expected = "verification key and signature list lengths differ")]
fn unequal_length_aggregation() {
    let mut rng = test_rng();
    let scheme = Scheme::new(&mut rng);
    let (verification_key,_) = key_gen(&mut rng);

    scheme.aggregate_concealed_signatures(&[verification_key], &[]);
}

#[test]
#[should_panic(expected = "empty verify key list")]
fn empty_input_aggregation() {
    let scheme = Scheme::new(&mut test_rng());

    scheme.aggregate_concealed_signatures(&[], &[]);
}

#[test]
fn verify_opening() {
    let mut rng = test_rng();
    let messages: &[&[u8]] = &[
        b"aggregate message one",
        b"aggregate message two",
        b"aggregate message three",
    ];
    let (scheme, verification_keys, concealed_signatures, aggregate) =
        generete_agg_tests(&mut rng, messages);

    let opening =
        scheme.local_aggregate_opening(&aggregate, &verification_keys, &concealed_signatures, 1);

    assert!(scheme.local_verify(
        &verification_keys[1],
        &aggregate,
        &opening,
        &concealed_signatures[1]
    ));
}

#[test]
fn wrong_opening() {
    let messages: &[&[u8]] = &[b"test message 1", b"test message 2", b"test message 3"];

    let (scheme, verification_keys, concealed_signatures, aggregate) =
        generete_agg_tests(&mut test_rng(), messages);

    let opening1 =
        scheme.local_aggregate_opening(&aggregate, &verification_keys, &concealed_signatures, 1);
    let opening2 =
        scheme.local_aggregate_opening(&aggregate, &verification_keys, &concealed_signatures, 2);

    assert!(scheme.local_verify(
        &verification_keys[1],
        &aggregate,
        &opening1,
        &concealed_signatures[1]
    ));
    assert!(!scheme.local_verify(
        &verification_keys[1],
        &aggregate,
        &opening2,
        &concealed_signatures[1]
    ));
}
