//! (Modified) AMF Franking Algorithms (KeyGen, Frank, Verify, RPJudge, SPJudge)
//! and forgery algorithms (Forge, RForge, SPForge, RPForge, SPRForge, RPRForge, SPRPForge)
//!
//! Cf. Fig. 5.2 in [HonoursProject].
//!
//! [HonoursProject]: See "Message Reporting for Interoperable End-to-End Encrypted Messaging Services"
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
    ReceiverPlatformJudge,
    SenderPlatformJudge,
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

/// The internal Fiat-Shamir signature used in AMF, denoted by pi in Chapter 5 of [HonoursProject].
pub(crate) type AMFInternalSignature = FiatShamirSignature<
    (
        OrProverCommitment<RistrettoPoint, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
        OrProverCommitment<RistrettoPoint, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
        OrProverCommitment<ChaumPedersenProverCommitment, RistrettoPoint>,
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
    ),
>;

/// The external AMF signature, denoted by sigma in Chapter 5 of [HonoursProject].
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AMFSignature {
    pub pi: AMFInternalSignature,
    pub RP: RistrettoPoint,
    pub R: RistrettoPoint,
    pub SP: RistrettoPoint,
    pub E_RP: RistrettoPoint,
    pub E_R: RistrettoPoint,
    pub E_SP: RistrettoPoint,
}

macro_rules! sample {
    ($($x:ident),*) => {
        let mut rng = rand::thread_rng();
        $(
            let $x = Scalar::random(&mut rng);
        )*
    };
}

pub fn keygen(role: AMFRole) -> (AMFPublicKey, AMFSecretKey) {
    // cf. Fig. 5 in [AMF]
    let mut rng = rand::thread_rng();
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);
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
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon);

    let RP = alpha * rp_public_key.public_key;
    let R = beta * recipient_public_key.public_key;
    let SP = epsilon * sp_public_key.public_key;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
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
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn verify(
    recipient_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.R == recipient_secret_key.secret_key * amf_signature.E_R;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        amf_signature.RP,
        amf_signature.R,
        amf_signature.SP,
        amf_signature.E_RP,
        amf_signature.E_SP,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn rp_judge(
    rp_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.RP == rp_secret_key.secret_key * amf_signature.E_RP;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        amf_signature.RP,
        amf_signature.R,
        amf_signature.SP,
        amf_signature.E_RP,
        amf_signature.E_SP,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn sp_judge(
    sp_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
) -> bool {
    let b1 = amf_signature.SP == sp_secret_key.secret_key * amf_signature.E_SP;

    let spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        amf_signature.RP,
        amf_signature.R,
        amf_signature.SP,
        amf_signature.E_RP,
        amf_signature.E_SP,
    );
    let b2 = spok.verify(message, amf_signature.pi);

    b1 && b2
}

pub fn forge(
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, gamma, delta, eta);

    let RP = gamma * g;
    let R = delta * g;
    let SP = eta * g;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
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
                    s1_witness: Some(gamma),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn r_forge(
    sender_public_key: AMFPublicKey,
    recipient_secret_key: AMFSecretKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, gamma, eta);

    let recipient_public_key = recipient_secret_key.secret_key * g;

    let RP = gamma * g;
    let R = beta * recipient_public_key;
    let SP = eta * g;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key.public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
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
                    s1_witness: Some(gamma),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn sp_forge(
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    sp_secret_key: AMFSecretKey,
    rp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, gamma, delta);

    let sp_public_key = sp_secret_key.secret_key * g;

    let RP = gamma * g;
    let R = delta * g;
    let SP = epsilon * sp_public_key;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
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
                    s1_witness: Some(epsilon * sp_secret_key.secret_key),
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
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn rp_forge(
    sender_public_key: AMFPublicKey,
    _recipient_public_key: AMFPublicKey,
    rp_secret_key: AMFSecretKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, delta, eta);

    let rp_public_key = rp_secret_key.secret_key * g;

    let RP = alpha * rp_public_key;
    let R = delta * g;
    let SP = eta * g;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key,
        sp_public_key.public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(alpha * rp_secret_key.secret_key),
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
                    s1_witness: Some(alpha * rp_secret_key.secret_key),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn rp_r_forge(
    sender_public_key: AMFPublicKey,
    rp_secret_key: AMFSecretKey,
    recipient_secret_key: AMFSecretKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, eta);

    let rp_public_key = rp_secret_key.secret_key * g;
    let recipient_public_key = recipient_secret_key.secret_key * g;

    let RP = alpha * rp_public_key;
    let R = beta * recipient_public_key;
    let SP = eta * g;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key,
        sp_public_key.public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(alpha * rp_secret_key.secret_key),
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
                    s1_witness: Some(alpha * rp_secret_key.secret_key),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn sp_r_forge(
    sender_public_key: AMFPublicKey,
    sp_secret_key: AMFSecretKey,
    recipient_secret_key: AMFSecretKey,
    rp_public_key: AMFPublicKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon, gamma);

    let sp_public_key = sp_secret_key.secret_key * g;
    let recipient_public_key = recipient_secret_key.secret_key * g;

    let RP = gamma * g;
    let R = beta * recipient_public_key;
    let SP = epsilon * sp_public_key;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key.public_key,
        sp_public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
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
                    s1_witness: Some(epsilon * sp_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(beta * recipient_secret_key.secret_key),
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(gamma),
                },
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
    }
}

pub fn rp_sp_forge(
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    rp_secret_key: AMFSecretKey,
    sp_secret_key: AMFSecretKey,
    message: &[u8],
) -> AMFSignature {
    let g = RistrettoBasepointTable::basepoint(RISTRETTO_BASEPOINT_TABLE);

    sample!(alpha, beta, epsilon);

    let rp_public_key = rp_secret_key.secret_key * g;
    let sp_public_key = sp_secret_key.secret_key * g;

    let RP = alpha * rp_public_key;
    let R = beta * recipient_public_key.public_key;
    let SP = epsilon * sp_public_key;
    let E_RP = alpha * g;
    let E_R = beta * g;
    let E_SP = epsilon * g;

    let mut spok = AMFSPoK::new(
        sender_public_key.public_key,
        rp_public_key,
        sp_public_key,
        RP,
        R,
        SP,
        E_RP,
        E_SP,
    );
    let pi = spok.sign(
        FiatShamirSecretKey {
            witness: (
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(alpha * rp_secret_key.secret_key),
                },
                OrWitness {
                    b: false,
                    s0_witness: Some(alpha),
                    s1_witness: None,
                },
                OrWitness {
                    b: true,
                    s0_witness: None,
                    s1_witness: Some(epsilon * sp_secret_key.secret_key),
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
            ),
        },
        message,
    );
    AMFSignature {
        pi,
        RP,
        R,
        SP,
        E_RP,
        E_R,
        E_SP,
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
        // 2. Initialize RP Judge
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        // 3. Initialize SP Judge
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        // 4. Initialize a message
        let message = b"hello world!";

        // 5. Frank the message
        let amf_signature = frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
        );

        // 6. Verify the message
        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        // 7. Judge the message (RP)
        let judging_result_j = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_j);

        // 8. Judge the message (SP)
        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_sp);
    }

    #[test]
    fn test_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        // Forge an AMF signature for "universal deniability"
        let amf_signature = forge(
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        // Forge the AMF signature using the recipient's secret key
        // This enables "receiver compromise deniability"
        let amf_signature = r_forge(
            sender_public_key,
            recipient_secret_key,
            rp_public_key,
            sp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_rp_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability" for RP
        let amf_signature = rp_forge(
            sender_public_key,
            recipient_public_key,
            rp_secret_key,
            sp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_sp_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        // Forge an AMF signature for "judge compromise deniability" for SP
        let amf_signature = sp_forge(
            sender_public_key,
            recipient_public_key,
            sp_secret_key,
            rp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_rp_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        let amf_signature = rp_r_forge(
            sender_public_key,
            rp_secret_key,
            recipient_secret_key,
            sp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_sp_r_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        let amf_signature = sp_r_forge(
            sender_public_key,
            sp_secret_key,
            recipient_secret_key,
            rp_public_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(!judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }

    #[test]
    fn test_rp_sp_forge() {
        let (sender_public_key, _sender_secret_key) = keygen(AMFRole::Sender);
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

        let message = b"hello world!";

        let amf_signature = rp_sp_forge(
            sender_public_key,
            recipient_public_key,
            rp_secret_key,
            sp_secret_key,
            message,
        );

        let verification_result = verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(verification_result);

        let judging_result_rp = rp_judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_rp);

        let judging_result_sp = sp_judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
        );
        assert!(judging_result_sp);

        let spok = AMFSPoK::new(
            sender_public_key.public_key,
            rp_public_key.public_key,
            sp_public_key.public_key,
            amf_signature.RP,
            amf_signature.R,
            amf_signature.SP,
            amf_signature.E_RP,
            amf_signature.E_SP,
        );
        assert!(spok.verify(message, amf_signature.pi));
    }
}
