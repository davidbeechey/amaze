//! Signature Proof of Knowledge for the AMF Relation
//!
//! Cf. Fig. 5 in [AMF]
//!
//! [AMF]: https://eprint.iacr.org/2019/565/20190527:092413
#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::pok::{
    and_proof::{AndProver, AndVerifier},
    chaum_pedersen::{
        ChaumPedersenProver, ChaumPedersenProverCommitment, ChaumPedersenVerifier,
        ChaumPedersenWitnessStatement,
    },
    fiat_shamir::FiatShamir,
    or_proof::{OrProver, OrProverResponse, OrVerifier, OrWitness},
    schnorr::{SchnorrProver, SchnorrVerifier},
};

pub type AMFSPoK = FiatShamir<
    (
        OrWitness<Scalar, Scalar>,
        OrWitness<Scalar, Scalar>,
        OrWitness<Scalar, Scalar>,
        OrWitness<Scalar, Scalar>,
    ),
    (
        // sender_public_key = g^t and J = g^u (cf. Fig 5 of [AMF])
        (RistrettoPoint, RistrettoPoint),
        // J = judge_public_key^v && E_j = g^v and R = g^w (cf. Fig 5 of [AMF])
        (ChaumPedersenWitnessStatement, RistrettoPoint),
        // sender_public_key = g^t and M = g^x (cf. Fig 5 of [AMF])
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenWitnessStatement, RistrettoPoint),
    ),
    (
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
    ),
>;

impl AMFSPoK {
    pub fn new(
        sender_public_key: RistrettoPoint,
        judge_public_key: RistrettoPoint,
        m_public_key: RistrettoPoint,
        J: RistrettoPoint,
        R: RistrettoPoint,
        M: RistrettoPoint,
        E_J: RistrettoPoint,
        E_M: RistrettoPoint,
    ) -> Self {
        // 0. Initialize Schnorr for the statement sender_public_key = g^t; cf. Fig 5 of [AMF]
        let s0_prover = SchnorrProver::new(sender_public_key);
        let s0_verifier = SchnorrVerifier::new(sender_public_key);

        // 1. Initialize Schnorr for the statement J = g^u; cf. Fig 5 of [AMF]
        let s1_prover = SchnorrProver::new(J);
        let s1_verifier = SchnorrVerifier::new(J);

        // 2. Combine the Schnorr proofs s0 and s1 into an OR proof or0
        let or0_prover = OrProver {
            s0_prover: Box::new(s0_prover),
            s0_verifier: Box::new(s0_verifier),
            s1_prover: Box::new(s1_prover),
            s1_verifier: Box::new(s1_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or0_verifier = OrVerifier {
            s0_verifier: Box::new(s0_verifier),
            s1_verifier: Box::new(s1_verifier),
        };

        // 3. Initialize Chaum-Pedersen for the statement (J = judge_public_key^v && E_j = g^v); cf. Fig 5 of [AMF]
        let s3_witness_statement = ChaumPedersenWitnessStatement {
            u: judge_public_key,
            v: E_J,
            w: J,
        };
        let s2_prover = ChaumPedersenProver::new(s3_witness_statement);
        let s2_verifier = ChaumPedersenVerifier::new(s3_witness_statement);

        // 4. Initialize Schnorr for the statement R = g^w; cf. Fig 5 of [AMF]
        let s3_prover = SchnorrProver::new(R);
        let s3_verifier = SchnorrVerifier::new(R);

        // 5. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
        let or1_prover = OrProver {
            s0_prover: Box::new(s2_prover),
            s0_verifier: Box::new(s2_verifier),
            s1_prover: Box::new(s3_prover),
            s1_verifier: Box::new(s3_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or1_verifier = OrVerifier {
            s0_verifier: Box::new(s2_verifier),
            s1_verifier: Box::new(s3_verifier),
        };

        // NEW: support a new clause to add a second moderator

        // Initialize Schnorr for the statement sender_public_key = g^t; cf. Fig 5 of [AMF]
        let s4_prover = SchnorrProver::new(sender_public_key);
        let s4_verifier = SchnorrVerifier::new(sender_public_key);

        // Initialize Schnorr for the statement M = g^x; cf. Fig 5 of [AMF]
        let s5_prover = SchnorrProver::new(M);
        let s5_verifier = SchnorrVerifier::new(M);

        // Combine the Schnorr proofs s4 and s5 into an OR proof or2
        let or2_prover = OrProver {
            s0_prover: Box::new(s4_prover),
            s0_verifier: Box::new(s4_verifier),
            s1_prover: Box::new(s5_prover),
            s1_verifier: Box::new(s5_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or2_verifier = OrVerifier {
            s0_verifier: Box::new(s4_verifier),
            s1_verifier: Box::new(s5_verifier),
        };

        // NEW: clause for receiver verification that second moderator will judge the message

        let s6_witness_statement = ChaumPedersenWitnessStatement {
            u: judge_public_key,
            v: E_J,
            w: J,
        };
        let s6_prover = ChaumPedersenProver::new(s6_witness_statement);
        let s6_verifier = ChaumPedersenVerifier::new(s6_witness_statement);

        // 4. Initialize Schnorr for the statement R = g^w; cf. Fig 5 of [AMF]
        let s7_prover = SchnorrProver::new(R);
        let s7_verifier = SchnorrVerifier::new(R);

        // 5. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
        let or3_prover = OrProver {
            s0_prover: Box::new(s6_prover),
            s0_verifier: Box::new(s6_verifier),
            s1_prover: Box::new(s7_prover),
            s1_verifier: Box::new(s7_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or3_verifier = OrVerifier {
            s0_verifier: Box::new(s6_verifier),
            s1_verifier: Box::new(s7_verifier),
        };

        // 6. Combine the OR proofs or0 and or1 into an AND proof and
        let and_prover = AndProver {
            s0_prover: Box::new(or0_prover),
            s1_prover: Box::new(or1_prover),
            s2_prover: Box::new(or2_prover),
            s3_prover: Box::new(or3_prover),
        };
        let and_verifier = AndVerifier {
            s0_verifier: Box::new(or0_verifier),
            s1_verifier: Box::new(or1_verifier),
            s2_verifier: Box::new(or2_verifier),
            s3_verifier: Box::new(or3_verifier),
        };

        // 7. Finally, create a Fiat-Shamir Signature Scheme from the AND proof and

        FiatShamir {
            prover: Box::from(and_prover),
            verifier: Box::from(and_verifier),
        }
    }
}
