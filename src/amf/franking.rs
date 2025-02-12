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
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
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
    pub J_1: RistrettoPoint,
    pub J_2: RistrettoPoint,
    pub R: RistrettoPoint,
    pub M_1: RistrettoPoint,
    pub M_2: RistrettoPoint,
    pub E_J: RistrettoPoint,
    pub E_R: RistrettoPoint,
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
    let iota = Scalar::random(&mut rng);
    let kappa = Scalar::random(&mut rng);

    let J_1 = alpha * judge_public_key.public_key;
    let J_2 = iota * judge_public_key.public_key;
    let R = beta * recipient_public_key.public_key;
    let M_1 = epsilon * m_public_key.public_key;
    let M_2 = kappa * m_public_key.public_key;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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
    let b1 = amf_signature.R == recipient_secret_key.secret_key * amf_signature.E_R;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J_1,
        amf_signature.J_2,
        amf_signature.R,
        amf_signature.M_1,
        amf_signature.M_2,
        amf_signature.E_J,
        amf_signature.E_M,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    println!("b1: {}", b1);
    println!("b2: {}", b2);

    b1 && b2
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
    let b1 = amf_signature.J_1 == judge_secret_key.secret_key * amf_signature.E_J;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J_1,
        amf_signature.J_2,
        amf_signature.R,
        amf_signature.M_1,
        amf_signature.M_2,
        amf_signature.E_J,
        amf_signature.E_M,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn m_judge(
    m_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    judge_public_key: AMFPublicKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.M_1 == m_secret_key.secret_key * amf_signature.E_M;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        amf_signature.J_1,
        amf_signature.J_2,
        amf_signature.R,
        amf_signature.M_1,
        amf_signature.M_2,
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

    // J_1
    let alpha = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let iota = Scalar::random(&mut rng);

    let J_1 = gamma * g;
    let J_2 = mu * g;
    let R = delta * g;
    let M_1 = eta * g;
    let M_2 = iota * g;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                    s1_witness: Some(delta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(mu),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(iota),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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

    // J_1
    let alpha = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let _delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let iota = Scalar::random(&mut rng);

    let recipient_public_key = recipient_secret_key.secret_key * g;

    let J_1 = gamma * g;
    let J_2 = mu * g;
    let R = beta * recipient_public_key;
    let M_1 = eta * g;
    let M_2 = iota * g;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key.public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                    s1_witness: Some(beta * recipient_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(mu),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(iota),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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

    // J_1
    let alpha = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let _eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let _iota = Scalar::random(&mut rng);

    let m_public_key = m_secret_key.secret_key * g;

    let J_1 = gamma * g;
    let J_2 = mu * g;
    let R = delta * g;
    let M_1 = epsilon * m_public_key;
    let M_2 = kappa * m_public_key;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(kappa * m_secret_key.secret_key),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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

    // J_1
    let alpha = Scalar::random(&mut rng);
    let _gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let _mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let iota = Scalar::random(&mut rng);

    let judge_public_key = judge_secret_key.secret_key * g;

    let J_1 = alpha * judge_public_key;
    let J_2 = lambda * judge_public_key;
    let R = delta * g;
    let M_1 = eta * g;
    let M_2 = iota * g;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key,
        m_public_key.public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                    s1_witness: Some(delta),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(lambda * judge_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(iota),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
        E_M,
    }
}

pub fn j_r_forge(
    sender_public_key: AMFPublicKey,
    judge_secret_key: AMFSecretKey,
    recipient_secret_key: AMFSecretKey,
    m_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]

    // J_1
    let alpha = Scalar::random(&mut rng);
    let _gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let _mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let _delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let iota = Scalar::random(&mut rng);

    let judge_public_key = judge_secret_key.secret_key * g;
    let recipient_public_key = recipient_secret_key.secret_key * g;

    let J_1 = alpha * judge_public_key;
    let J_2 = lambda * judge_public_key;
    let R = beta * recipient_public_key;
    let M_1 = eta * g;
    let M_2 = iota * g;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key,
        m_public_key.public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                    s1_witness: Some(beta * recipient_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(lambda * judge_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(iota),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
        E_M,
    }
}

pub fn m_r_forge(
    sender_public_key: AMFPublicKey,
    m_secret_key: AMFSecretKey,
    recipient_secret_key: AMFSecretKey,
    judge_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
    // cf. Fig. 5 in [AMF]

    // J_1
    let alpha = Scalar::random(&mut rng);
    let gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let mu = Scalar::random(&mut rng);

    // R_1
    let beta = Scalar::random(&mut rng);
    let _delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let _eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let _iota = Scalar::random(&mut rng);

    let m_public_key = m_secret_key.secret_key * g;
    let recipient_public_key = recipient_secret_key.secret_key * g;

    let J_1 = gamma * g;
    let J_2 = mu * g;
    let R = beta * recipient_public_key;
    let M_1 = epsilon * m_public_key;
    let M_2 = kappa * m_public_key;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key.public_key,
        m_public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                    s1_witness: Some(epsilon * m_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(beta * recipient_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(mu),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(kappa * m_secret_key.secret_key),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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

    // J_1
    let alpha = Scalar::random(&mut rng);
    let _gamma = Scalar::random(&mut rng);

    // J_2
    let lambda = Scalar::random(&mut rng);
    let _mu = Scalar::random(&mut rng);

    // R
    let beta = Scalar::random(&mut rng);
    let _delta = Scalar::random(&mut rng);

    // M_1
    let epsilon = Scalar::random(&mut rng);
    let _eta = Scalar::random(&mut rng);

    // M_2
    let kappa = Scalar::random(&mut rng);
    let _iota = Scalar::random(&mut rng);

    let judge_public_key = judge_secret_key.secret_key * g;
    let m_public_key = m_secret_key.secret_key * g;

    let J_1 = alpha * judge_public_key;
    let J_2 = lambda * judge_public_key;
    let R = beta * recipient_public_key.public_key;
    let M_1 = epsilon * m_public_key;
    let M_2 = kappa * m_public_key;
    let E_J = alpha * g;
    let E_R = beta * g;
    let E_M = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        judge_public_key,
        m_public_key,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
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
                OrWitness {
                    b: false,
                    s0_witness: Some(epsilon),
                    s1_witness: None,
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        J_1,
        J_2,
        R,
        M_1,
        M_2,
        E_J,
        E_R,
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_j_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability"
        let amf_signature = j_r_forge(
            sender_public_key,
            judge_secret_key,
            recipient_secret_key,
            m_public_key,
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

        // The forged signature should be judged by J
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

        // The forged signature should not be judged by M
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_m_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);
        let (m_public_key, m_secret_key) = keygen(AMFRole::Judge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability"
        let amf_signature = m_r_forge(
            sender_public_key,
            m_secret_key,
            recipient_secret_key,
            judge_public_key,
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

        // The forged signature should not be judged by J
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

        // The forged signature should be judged by M
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

        // The forged signature should look valid
        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            judge_public_key.public_key,
            m_public_key.public_key,
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
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
            amf_signature.J_1,
            amf_signature.J_2,
            amf_signature.R,
            amf_signature.M_1,
            amf_signature.M_2,
            amf_signature.E_J,
            amf_signature.E_M,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }
}
