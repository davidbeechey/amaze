//! AMF Franking Algorithms (KeyGen, Frank, Verify, Judge)
//!
//! Cf. Fig. 5 in [AMF]
//!
//! [AMF]: https://eprint.iacr.org/2019/565/20190527:092413
#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};

use crate::pok::{
    chaum_pedersen::ChaumPedersenProverCommitment,
    fiat_shamir::{FiatShamirSecretKey, FiatShamirSignature, SignatureScheme},
    or_proof::{OrProverCommitment, OrProverResponse, OrWitness},
};

use super::spok_amf::AMFSPoK;

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum AMFRole {
    Sender,
    Recipient,
    Judge,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AMFPublicKey {
    pub role: AMFRole,
    pub public_key: RistrettoPoint,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AMFSecretKey {
    pub role: AMFRole,
    pub secret_key: Scalar,
}

/// The internal Fiat-Shamir signature used in AMF, denoted by pi in Fig. 5 of [AMF].
pub(crate) type AMFInternalSignature = FiatShamirSignature<
    (
        OrProverCommitment<RistrettoPoint, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
        OrProverCommitment<RistrettoPoint, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
    ),
>;

/// The external AMF signature, denoted by sigma in Fig. 5 of [AMF].
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AMFSignature {
    pub pi: AMFInternalSignature,
    pub J: RistrettoPoint,
    pub R_1: RistrettoPoint,
    pub R_2: RistrettoPoint,
    pub M: RistrettoPoint,
    pub E_J: RistrettoPoint,
    pub E_R_1: RistrettoPoint,
    pub E_R_2: RistrettoPoint,
    pub E_M: RistrettoPoint,
}

pub fn keygen(role: AMFRole) -> (AMFPublicKey, AMFSecretKey) {
    // cf. Fig. 5 in [AMF]
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    let secret_key = Scalar::random(&mut rng);
    let public_key = secret_key * g;
    (
        AMFPublicKey { role, public_key },
        AMFSecretKey { role, secret_key },
    )
}

pub fn frank(
    sender_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);

    let J = alpha * judge_public_key.public_key;
    let R_1 = beta * recipient_public_key.public_key;
    let R_2 = zeta * recipient_public_key.public_key;
    let M = epsilon * m_public_key.public_key;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: false,
                    s0_witness: Some(sender_secret_key.secret_key),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(sender_secret_key.secret_key),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

pub fn verify(
    recipient_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.R_1 == recipient_secret_key.secret_key * amf_signature.E_R_1;
    let b2 = amf_signature.R_2 == recipient_secret_key.secret_key * amf_signature.E_R_2;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J,
        amf_signature.R_1,
        amf_signature.R_2,
        amf_signature.M,
        amf_signature.E_J,
        amf_signature.E_M,
    );
    let b3 = spok.verify(message, amf_signature.pi);

    println!("b1: {}", b1);
    println!("b2: {}", b2);
    println!("b3: {}", b3);

    b1 && b2 && b3
}

pub fn j_judge(
    judge_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.J == judge_secret_key.secret_key * amf_signature.E_J;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J,
        amf_signature.R_1,
        amf_signature.R_2,
        amf_signature.M,
        amf_signature.E_J,
        amf_signature.E_M,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

/// New function used by the second judge (M) to judge the message
pub fn m_judge(
    m_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.M == m_secret_key.secret_key * amf_signature.E_M;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J,
        amf_signature.R_1,
        amf_signature.R_2,
        amf_signature.M,
        amf_signature.E_J,
        amf_signature.E_M,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn forge(
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);

    let delta = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);
    let theta = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    let J = gamma * g;
    let R_1 = delta * g;
    let R_2 = theta * g;
    let M = eta * g;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(gamma),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(delta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(eta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(theta),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

pub fn r_forge(
    sender_public_key: AMFPublicKey,
    recipient_secret_key: AMFSecretKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);

    let recipient_public_key = recipient_secret_key.secret_key * g;

    let J = gamma * g;
    let R_1 = beta * recipient_public_key;
    let R_2 = zeta * recipient_public_key;
    let M = eta * g;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(gamma),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(beta * recipient_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(eta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(zeta * recipient_secret_key.secret_key),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

pub fn j_forge(
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    judge_secret_key: AMFSecretKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let theta = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    let judge_public_key = judge_secret_key.secret_key * g;

    let J = alpha * judge_public_key;
    let R_1 = beta * recipient_public_key.public_key;
    let R_2 = theta * g;
    let M = eta * g;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key,
        m_public_key.public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(alpha * judge_secret_key.secret_key),
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(eta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(theta),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

pub fn m_forge(
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    m_secret_key: AMFSecretKey,
    judge_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let delta = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);

    let m_public_key = m_secret_key.secret_key * g;

    let J = gamma * g;
    let R_1 = delta * g;
    let R_2 = zeta * recipient_public_key.public_key;
    let M = epsilon * m_public_key;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(gamma),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(delta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(epsilon * m_secret_key.secret_key),
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

pub fn j_m_forge(
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    judge_secret_key: AMFSecretKey,
    m_secret_key: AMFSecretKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let epsilon = Scalar::random(&mut rng);
    let zeta = Scalar::random(&mut rng);

    let judge_public_key = judge_secret_key.secret_key * g;
    let m_public_key = m_secret_key.secret_key * g;

    let J = alpha * judge_public_key;
    let R_1 = beta * recipient_public_key.public_key;
    let R_2 = zeta * recipient_public_key.public_key;
    let M = epsilon * m_public_key;
    let E_J = alpha * g;
    let E_R_1 = beta * g;
    let E_R_2 = zeta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key,
        m_public_key,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_M,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(alpha * judge_secret_key.secret_key),
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(epsilon * m_secret_key.secret_key),
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J,
        R_1,
        R_2,
        M,
        E_J,
        E_R_1,
        E_R_2,
        E_M,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_franking() {
        // 0. Initialize a Sender
        let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
        // 1. Initialize a Recipient
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        // 2. Initialize a Judge
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        // 3. Initialize a second Judge (M)
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        // 3. Initialize a message
        let message = b"hello world!";

        // 4. Frank the message
        let amf_signature = frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
        );

        // 5. Verify the message
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        // 6. Judge the message (J)
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_j);

        // 7. Judge the message (M)
        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_m);
    }

    #[test]
    fn test_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "universal deniability"
        let amf_signature = forge(
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
        );

        // The forged signature should NOT be verified by the recipient
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        // The forged signature should NOT be judged by the judge, as the judge can detect the forgery
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_j);

        // The forged signature should NOT be judged by the other judge
        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_m);

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J,
            amf_signature.R_1,
            amf_signature.R_2,
            amf_signature.M,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge the AMF signature using the recipient's secret key
        // This enables "receiver compromise deniability"
        let amf_signature = r_forge(
            sender_public_key,
            recipient_secret_key,
            judge_public_key,
            m_public_key,
            message,
        );

        // The forged signature should be verified by any party with the recipient's secret key
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        // The forged signature should NOT be judged by the judge, as the judge can detect the forgery
        // This is what maintains "receiver binding"
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_j);

        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_m);

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J,
            amf_signature.R_1,
            amf_signature.R_2,
            amf_signature.M,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_j_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability"
        let amf_signature = j_forge(
            sender_public_key,
            recipient_public_key,
            judge_secret_key,
            m_public_key,
            message,
        );

        // The forged signature should be not verified by the recipient
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        // The forged signature should be judged by the judge
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_j);

        // The forged signature should not be judged by the other judge
        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_m);

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J,
            amf_signature.R_1,
            amf_signature.R_2,
            amf_signature.M,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_m_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability"
        let amf_signature = m_forge(
            sender_public_key,
            recipient_public_key,
            m_secret_key,
            judge_public_key,
            message,
        );

        // The forged signature should not be verified by the recipient
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        // The forged signature should be judged by the judge
        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_m);

        // The forged signature should not be judged by the other judge
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_j);

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J,
            amf_signature.R_1,
            amf_signature.R_2,
            amf_signature.M,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_j_m_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability"
        let amf_signature = j_m_forge(
            sender_public_key,
            recipient_public_key,
            judge_secret_key,
            m_secret_key,
            message,
        );

        // The forged signature should verified by the recipient
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        // The forged signature should be judged by the judge
        let judging_result_m = m_judge(
            m_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_m);

        // The forged signature should not be judged by the other judge
        let judging_result_j = j_judge(
            judge_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            m_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_j);

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J,
            amf_signature.R_1,
            amf_signature.R_2,
            amf_signature.M,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }
}
