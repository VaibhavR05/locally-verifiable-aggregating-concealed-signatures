use ark_std::test_rng;
use lvacs::Scheme;

fn main() {
    // TODO:
    // Implement custom errors for specific use cases that are being handled by panics right now

    let rng = &mut test_rng();

    // ----- SETUP -----

    // Start by initializing a scheme.
    // This automatically generates the required parameters for all signatures
    let lvacs = Scheme::new(rng);

    // Generate keys with a custom controlled rng
    let (vk, sk) = lvacs.key_gen(rng);

    // ----- BLS -----

    // Sign a message with sk
    let message = b"Sign Me!!";
    let bls_signature = lvacs.sign(&sk, message).unwrap();

    // You can verify each signature with vk
    assert!(lvacs.verify(&vk, message, &bls_signature).unwrap());

    // ----- CONCEALED SIGNATURES -----

    // Convert an existing signature to a concealed signature and auxilary data
    let (concealed_sig, aux) = lvacs.convert(&vk, message, &bls_signature, rng).unwrap();

    // Verification for concealed signature is similar (this is bool and not Result<bool,_> for now)
    assert!(lvacs.verify_concealed(&concealed_sig, &vk));

    // Open a concealed signature to prove validity
    assert!(
        lvacs
            .open_concealed_signature(message, &concealed_sig, &aux)
            .unwrap()
    );

    // ----- AGGREGATE SIGNATURES -----

    // Create signatures with different keys for demonstration
    let (vk0, sk1) = lvacs.key_gen(rng);
    let (vk1, sk2) = lvacs.key_gen(rng);
    let vk_list = [vk0.clone(), vk1.clone()];

    let m0 = b"Aggregate message 1";
    let m1 = b"Aggregate message 2";

    let s0 = lvacs.sign(&sk1, m0).unwrap();
    let s1 = lvacs.sign(&sk2, m1).unwrap();

    let (cs0, _aux1) = lvacs.convert(&vk0, m0, &s0, rng).unwrap();
    let (cs1, _aux2) = lvacs.convert(&vk1, m1, &s1, rng).unwrap();
    let sig_list = [cs0.clone(), cs1.clone()];

    // Aggregate multiple signatures
    let aggregate_sig = lvacs.aggregate_concealed_signatures(&vk_list, &sig_list);

    // Verify the aggregate signature with all VerifyKeys
    assert!(lvacs.verify_aggregate(&vk_list, &aggregate_sig));

    // ----- LOCAL OPENINGS -----

    // Create local openings w.r.t a particular verification key
    let opening1 = lvacs.local_aggregate_opening(&aggregate_sig, &vk_list, &sig_list, 1);

    // Verify aggregate signatures with a local opening and signature
    assert!(lvacs.local_verify(&vk1, &aggregate_sig, &opening1, &cs1));
}
