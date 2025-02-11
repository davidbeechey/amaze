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
        (ChaumPedersenWitnessStatement, RistrettoPoint),
        (ChaumPedersenWitnessStatement, RistrettoPoint),
    ),
    (
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
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

impl AMFSPoK {
    pub fn new(
        sender_public_key: RistrettoPoint,
        judge_public_key: RistrettoPoint,
        m_public_key: RistrettoPoint,
        J_1: RistrettoPoint,
        J_2: RistrettoPoint,
        R_1: RistrettoPoint,
        R_2: RistrettoPoint,
        M_1: RistrettoPoint,
        M_2: RistrettoPoint,
        E_J_1: RistrettoPoint,
        E_J_2: RistrettoPoint,
        E_M_1: RistrettoPoint,
        E_M_2: RistrettoPoint,
    ) -> Self {
        // 0. [FIRST CLAUSE] Initialize Schnorr for the statement sender_public_key = g^t
        let s0_prover = SchnorrProver::new(sender_public_key);
        let s0_verifier = SchnorrVerifier::new(sender_public_key);

        // 1. [FIRST CLAUSE] Initialize Schnorr for the statement J_1 = g^u
        let s1_prover = SchnorrProver::new(J_1);
        let s1_verifier = SchnorrVerifier::new(J_1);

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

        // 3. [SECOND CLAUSE] Initialize Chaum-Pedersen for the statement (J_1 = judge_public_key^v && E_j_1 = g^v)
        let s3_witness_statement = ChaumPedersenWitnessStatement {
            u: judge_public_key,
            v: E_J_1,
            w: J_1,
        };
        let s2_prover = ChaumPedersenProver::new(s3_witness_statement);
        let s2_verifier = ChaumPedersenVerifier::new(s3_witness_statement);

        // 4. [SECOND CLAUSE] Initialize Schnorr for the statement R_1 = g^w
        let s3_prover = SchnorrProver::new(R_1);
        let s3_verifier = SchnorrVerifier::new(R_1);

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

        // 6. [THIRD CLAUSE] Initialize Schnorr for the statement sender_public_key = g^t
        let s4_prover = SchnorrProver::new(sender_public_key);
        let s4_verifier = SchnorrVerifier::new(sender_public_key);

        // 7. [THIRD CLAUSE] Initialize Schnorr for the statement M_1 = g^x
        let s5_prover = SchnorrProver::new(M_1);
        let s5_verifier = SchnorrVerifier::new(M_1);

        // 8. Combine the Schnorr proofs s4 and s5 into an OR proof or2
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

        // 9. [FOURTH CLAUSE] Initialize Chaum-Pedersen for the statement (M_1 = m_public_key^y && E_m_1 = g^y)
        let s6_witness_statement = ChaumPedersenWitnessStatement {
            u: m_public_key,
            v: E_M_1,
            w: M_1,
        };
        let s6_prover = ChaumPedersenProver::new(s6_witness_statement);
        let s6_verifier = ChaumPedersenVerifier::new(s6_witness_statement);

        // 10. [FOURTH CLAUSE] Initialize Schnorr for the statement R_2 = g^w
        let s7_prover = SchnorrProver::new(R_2);
        let s7_verifier = SchnorrVerifier::new(R_2);

        // 11. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
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

        // 12. [FIFTH CLAUSE] Initialise Chaum-Pedersen for the statement (M_1 = m_public_key^y && E_m_1 = g^y)
        let s8_witness_statement = ChaumPedersenWitnessStatement {
            u: m_public_key,
            v: E_M_1,
            w: M_1,
        };
        let s8_prover = ChaumPedersenProver::new(s8_witness_statement);
        let s8_verifier = ChaumPedersenVerifier::new(s8_witness_statement);

        // 13. [FIFTH CLAUSE] Initialize Schnorr for the statement J_2 = g^u
        let s9_prover = SchnorrProver::new(J_2);
        let s9_verifier = SchnorrVerifier::new(J_2);

        // 14. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
        let or4_prover = OrProver {
            s0_prover: Box::new(s8_prover),
            s0_verifier: Box::new(s8_verifier),
            s1_prover: Box::new(s9_prover),
            s1_verifier: Box::new(s9_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or4_verifier = OrVerifier {
            s0_verifier: Box::new(s8_verifier),
            s1_verifier: Box::new(s9_verifier),
        };

        // 15. [SIXTH CLAUSE] Initialize Chaum-Pedersen for the statement (J_1 = judge_public_key^v && E_j_1 = g^v)
        let s10_witness_statement = ChaumPedersenWitnessStatement {
            u: judge_public_key,
            v: E_J_1,
            w: J_1,
        };
        let s10_prover = ChaumPedersenProver::new(s10_witness_statement);
        let s10_verifier = ChaumPedersenVerifier::new(s10_witness_statement);

        // 16. [SIXTH CLAUSE] Initialize Schnorr for the statement M_2 = g^w
        let s11_prover = SchnorrProver::new(M_2);
        let s11_verifier = SchnorrVerifier::new(M_2);

        // 17. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
        let or5_prover = OrProver {
            s0_prover: Box::new(s10_prover),
            s0_verifier: Box::new(s10_verifier),
            s1_prover: Box::new(s11_prover),
            s1_verifier: Box::new(s11_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or5_verifier = OrVerifier {
            s0_verifier: Box::new(s10_verifier),
            s1_verifier: Box::new(s11_verifier),
        };

        // 18. Combine the OR proofs or0 and or1 into an AND proof and
        let and_prover = AndProver {
            s0_prover: Box::new(or0_prover),
            s1_prover: Box::new(or1_prover),
            s2_prover: Box::new(or2_prover),
            s3_prover: Box::new(or3_prover),
            s4_prover: Box::new(or4_prover),
            s5_prover: Box::new(or5_prover),
        };
        let and_verifier = AndVerifier {
            s0_verifier: Box::new(or0_verifier),
            s1_verifier: Box::new(or1_verifier),
            s2_verifier: Box::new(or2_verifier),
            s3_verifier: Box::new(or3_verifier),
            s4_verifier: Box::new(or4_verifier),
            s5_verifier: Box::new(or5_verifier),
        };

        // 7. Finally, create a Fiat-Shamir Signature Scheme from the AND proof and
        FiatShamir {
            prover: Box::from(and_prover),
            verifier: Box::from(and_verifier),
        }
    }
}
