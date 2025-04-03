//! Signature Proof of Knowledge for the AMF Relation
//!
//! Cf. Fig. 5.2 of [HonoursProject].
//!
//! [HonoursProject]: See "Message Reporting for Interoperable End-to-End Encrypted Messaging Services"
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
    ),
    (
        // sender_public_key = g^t and RP = g^u (cf. Fig 5.2 of [HonoursProject])
        (RistrettoPoint, RistrettoPoint),
        // RP = rp_public_key^v && E_rp = g^v and R = g^w (cf. Fig 5.2 of [HonoursProject])
        (ChaumPedersenWitnessStatement, RistrettoPoint),
        // sender_public_key = g^a and SP = g^b (cf. Fig 5.2 of [HonoursProject])
        (RistrettoPoint, RistrettoPoint),
        // SP = sp_public_key^c && E_sp = g^c and R = g^d (cf. Fig 5.2 of [HonoursProject])
        (ChaumPedersenWitnessStatement, RistrettoPoint),
        // SP = sp_public_key^e && E_sp = g^e and RP = g^f (cf. Fig 5.2 of [HonoursProject])
        (ChaumPedersenWitnessStatement, RistrettoPoint),
    ),
    (
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
    ),
>;

impl AMFSPoK {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_public_key: RistrettoPoint,
        rp_public_key: RistrettoPoint,
        sp_public_key: RistrettoPoint,
        RP: RistrettoPoint,
        R: RistrettoPoint,
        SP: RistrettoPoint,
        E_RP: RistrettoPoint,
        E_SP: RistrettoPoint,
    ) -> Self {
        // 0. [FIRST CLAUSE] Initialize Schnorr for the statement sender_public_key = g^t
        let s0_prover = SchnorrProver::new(sender_public_key);
        let s0_verifier = SchnorrVerifier::new(sender_public_key);

        // 1. [FIRST CLAUSE] Initialize Schnorr for the statement RP = g^u
        let s1_prover = SchnorrProver::new(RP);
        let s1_verifier = SchnorrVerifier::new(RP);

        // 2. [FIRST CLAUSE] Combine the Schnorr proofs s0 and s1 into an OR proof or0
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

        // 3. [SECOND CLAUSE] Initialize Chaum-Pedersen for the statement (RP = rp_public_key^v && E_rp = g^v)
        let s3_witness_statement = ChaumPedersenWitnessStatement {
            u: rp_public_key,
            v: E_RP,
            w: RP,
        };
        let s2_prover = ChaumPedersenProver::new(s3_witness_statement);
        let s2_verifier = ChaumPedersenVerifier::new(s3_witness_statement);

        // 4. [SECOND CLAUSE] Initialize Schnorr for the statement R_1 = g^w
        let s3_prover = SchnorrProver::new(R);
        let s3_verifier = SchnorrVerifier::new(R);

        // 5. [SECOND CLAUSE] Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
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

        // 6. [THIRD CLAUSE] Initialize Schnorr for the statement sender_public_key = g^a
        let s4_prover = SchnorrProver::new(sender_public_key);
        let s4_verifier = SchnorrVerifier::new(sender_public_key);

        // 7. [THIRD CLAUSE] Initialize Schnorr for the statement SP = g^b
        let s5_prover = SchnorrProver::new(SP);
        let s5_verifier = SchnorrVerifier::new(SP);

        // 8. [THIRD CLAUSE] Combine the Schnorr proofs s4 and s5 into an OR proof or2
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

        // 9. [FOURTH CLAUSE] Initialize Chaum-Pedersen for the statement (SP = sp_public_key^c && E_sp = g^c)
        let s6_witness_statement = ChaumPedersenWitnessStatement {
            u: sp_public_key,
            v: E_SP,
            w: SP,
        };
        let s6_prover = ChaumPedersenProver::new(s6_witness_statement);
        let s6_verifier = ChaumPedersenVerifier::new(s6_witness_statement);

        // 10. [FOURTH CLAUSE] Initialize Schnorr for the statement R = g^d
        let s7_prover = SchnorrProver::new(R);
        let s7_verifier = SchnorrVerifier::new(R);

        // 11. [FOURTH CLAUSE] Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
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

        // 12. [FIFTH CLAUSE] Initialise Chaum-Pedersen for the statement (SP = sp_public_key^e && E_sp = g^e)
        let s8_witness_statement = ChaumPedersenWitnessStatement {
            u: sp_public_key,
            v: E_SP,
            w: SP,
        };
        let s8_prover = ChaumPedersenProver::new(s8_witness_statement);
        let s8_verifier = ChaumPedersenVerifier::new(s8_witness_statement);

        // 13. [FIFTH CLAUSE] Initialize Schnorr for the statement RP = g^f
        let s9_prover = SchnorrProver::new(RP);
        let s9_verifier = SchnorrVerifier::new(RP);

        // 14. [FIFTH CLAUSE] Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
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

        // 18. Combine the OR proofs or0, or1, or2, or3 and or4 into an AND proof
        let and_prover = AndProver {
            s0_prover: Box::new(or0_prover),
            s1_prover: Box::new(or1_prover),
            s2_prover: Box::new(or2_prover),
            s3_prover: Box::new(or3_prover),
            s4_prover: Box::new(or4_prover),
        };
        let and_verifier = AndVerifier {
            s0_verifier: Box::new(or0_verifier),
            s1_verifier: Box::new(or1_verifier),
            s2_verifier: Box::new(or2_verifier),
            s3_verifier: Box::new(or3_verifier),
            s4_verifier: Box::new(or4_verifier),
        };

        // 7. Finally, create a Fiat-Shamir Signature Scheme from the AND proof
        FiatShamir {
            prover: Box::from(and_prover),
            verifier: Box::from(and_verifier),
        }
    }
}
