use ark_std::test_rng;
use lvacs::{
    AggregateSignature, AuxiliaryData, ConcealedSignature, Scheme, SignKey, Signature, VerifyKey,
    key_gen, sign,
};

const DEFAULT_SIZE: usize = 32;
const AGGREGATION_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32];

#[allow(dead_code)]
pub struct Dataset {
    scheme: Scheme,
    messages: Vec<Vec<u8>>,
    verification_keys: Vec<VerifyKey>,
    signing_keys: Vec<SignKey>,
    signatures: Vec<Signature>,
    concealed_signatures: Vec<ConcealedSignature>,
    auxiliary_data: Vec<AuxiliaryData>,
    aggregate: AggregateSignature,
}

#[allow(dead_code)]
impl Dataset {
    pub fn load(size: usize) -> Self {
        assert!(size > 0, "benchmark datasets must not be empty");

        let messages = generate_messages(size);
        let mut rng = test_rng();
        let scheme = Scheme::new(&mut rng);
        let mut verification_keys = Vec::with_capacity(size);
        let mut signing_keys = Vec::with_capacity(size);
        let mut signatures = Vec::with_capacity(size);
        let mut concealed_signatures = Vec::with_capacity(size);
        let mut auxiliary_data = Vec::with_capacity(size);

        for message in &messages {
            let (verification_key, signing_key) = key_gen(&mut rng);
            let signature = sign(&signing_key, message).expect("benchmark hashing should succeed");
            let (concealed_signature, aux) = scheme
                .convert(&verification_key, message, &signature, &mut rng)
                .expect("benchmark hashing should succeed");

            verification_keys.push(verification_key);
            signing_keys.push(signing_key);
            signatures.push(signature);
            concealed_signatures.push(concealed_signature);
            auxiliary_data.push(aux);
        }

        let aggregate =
            scheme.aggregate_concealed_signatures(&verification_keys, &concealed_signatures);

        Self {
            scheme,
            messages,
            verification_keys,
            signing_keys,
            signatures,
            concealed_signatures,
            auxiliary_data,
            aggregate,
        }
    }

    pub fn sizes() -> &'static [usize] {
        AGGREGATION_SIZES
    }

    pub fn default() -> Self {
        Self::load(DEFAULT_SIZE)
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub fn messages(&self) -> &[Vec<u8>] {
        &self.messages
    }

    pub fn verification_keys(&self) -> &[VerifyKey] {
        &self.verification_keys
    }

    pub fn signing_keys(&self) -> &[SignKey] {
        &self.signing_keys
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn concealed_signatures(&self) -> &[ConcealedSignature] {
        &self.concealed_signatures
    }

    pub fn auxiliary_data(&self) -> &[AuxiliaryData] {
        &self.auxiliary_data
    }

    pub fn aggregate(&self) -> &AggregateSignature {
        &self.aggregate
    }
}

fn generate_messages(size: usize) -> Vec<Vec<u8>> {
    (0..size)
        .map(|index| format!("LVACS benchmark message {index}").into_bytes())
        .collect()
}
