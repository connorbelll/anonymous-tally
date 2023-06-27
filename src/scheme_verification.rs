use crate::domain_separate::domain32;
use crate::group_operations::{
    divide, exponentiate, hash_to_point, multiply, random_point, random_scalar,
};
use crate::prove_dlog_or::produce_challenge;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Hash function domain separation bytes.
const REPORT_DOMAIN: u8 = 0u8;
const OR_CHALLENGE_DOMAIN: u8 = 3u8;

/// A successful result from the PreReport stage.
#[derive(Serialize, Deserialize, Debug)]
pub struct ReportVerification {
    /// Bit-string report.
    report: [u8; 32],
    /// Array of w values, one of which corresponds to the report.
    w_values: Vec<CompressedRistretto>,
    /// RHS coefficients, additional inputs to the challenge.
    y_values: Vec<CompressedRistretto>,
    /// The exponents for the LHS terms.
    z_values: Vec<Scalar>,
    /// The chosen challenges, which must all add up to the produced challenge, C.
    c_values: Vec<Scalar>,
}

/// Server 1 (restricted to verification) in our scheme.
pub struct Server1Verify {
    /// Mapping of users to user_pk.
    seen_w_values: HashSet<CompressedRistretto>,
}

/// Server 2 (restricted to verification) in our scheme.
pub struct Server2Verify {}

impl Server1Verify {
    pub fn new(known_w_values: HashSet<CompressedRistretto>) -> Server1Verify {
        Server1Verify {
            seen_w_values: known_w_values,
        }
    }

    /// Processes a verification proof and returns either the report identifier that has now been counted
    /// or an error.
    pub fn verify(&self, verification: &ReportVerification) -> Result<[u8; 32], &'static str> {
        // Check that we've seen all of the w values before.
        for x in verification.w_values.iter() {
            if !self.seen_w_values.contains(&x) {
                return Err("Unseen w value");
            }
        }

        // Check that each of the individual proofs checks out:
        // H(rep) ^ z_i == y_i * w ^ c_i
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, verification.report));

        for x in 1..100 {
            let z = verification.z_values[x];
            let y = verification.y_values[x];
            let w = verification.w_values[x];
            let c = verification.c_values[x];

            let lhs = exponentiate(h_report, z);
            let rhs = multiply(
                y.decompress().expect("Could not decompress y value"),
                exponentiate(w.decompress().expect("Could not decompress w value"), c),
            );
            if lhs.compress() != rhs.compress() {
                return Err("Found an invalid proof");
            }
        }

        // Check that Sum(c_i) = c, the overall challenge.
        let c = produce_challenge(
            OR_CHALLENGE_DOMAIN,
            verification.report,
            &verification.w_values,
            &verification.y_values,
        );
        let c_sum = verification.c_values.iter().sum();
        if c != c_sum {
            return Err("Challenges did not add up to correct c value.");
        }

        Ok(verification.report)
    }
}

impl Server2Verify {
    pub fn new() -> Server2Verify {
        Server2Verify {}
    }

    pub fn prove(
        &self,
        report: &[u8; 32],
        r: Scalar,
        other_reports: Vec<CompressedRistretto>,
    ) -> Result<ReportVerification, &'static str> {
        // Compute H(rep) for the base of the LHS (common to all proofs).
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, *report));

        // Compute the randomness for the "real" proof so we can compute the y value.
        let some_randomness = random_scalar();
        let some_randomness_pk = exponentiate(h_report, some_randomness);
        let real_w = exponentiate(h_report, r);

        // Choose k - 1 random values for z and c and compute the y that makes it true.
        let mut z_values: Vec<Scalar> = Vec::new();
        let mut c_values: Vec<Scalar> = Vec::new();
        let mut y_values: Vec<CompressedRistretto> = Vec::new();
        for x in other_reports.iter() {
            let z = random_scalar();
            let c = random_scalar();

            let lhs = exponentiate(h_report, z);
            let partial_rhs = exponentiate(x.decompress().expect("Unable to decompress point"), c);
            let y = divide(lhs, partial_rhs);

            z_values.push(z);
            c_values.push(c);
            y_values.push(y.compress());
        }

        // Put the "real" w and y values in the lists.
        let mut w_values = other_reports.clone();
        w_values.push(real_w.compress());
        y_values.push(some_randomness_pk.compress());

        // TODO: we need to shuffle the lists (all with identical shuffling) so that the verifier
        // doesn't know which proof is real (and this *must* happen before we generate the challenge).

        // Compute the real challenge.
        let mut c = produce_challenge(OR_CHALLENGE_DOMAIN, *report, &w_values, &y_values);
        for x in c_values.iter() {
            c -= x;
        }
        // c now has the value of the "real" challenge.
        c_values.push(c);

        // fill in the final value of c.
        let real_z = some_randomness + c * r;
        z_values.push(real_z);

        // TODO: the z_value and c_value lists also needs to be shuffled the same as the other lists.

        Ok(ReportVerification {
            report: *report,
            w_values: w_values,
            y_values: y_values,
            c_values: c_values,
            z_values: z_values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cool_asserts::assert_panics;

    #[test]
    fn prove_passes_verify() {
        let mut known_w_values = HashSet::new();
        // 99 fake reports
        for _x in 0..99 {
            known_w_values.insert(random_point().compress());
        }
        let other_reports: Vec<CompressedRistretto> = known_w_values.clone().into_iter().collect();

        // Randomly generate a report, then choose an r value to generate a known "w".
        let mut csprng = OsRng;
        let mut report = [0u8; 32];
        csprng.fill_bytes(&mut report);
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, report));
        let known_r = random_scalar();
        let known_w = exponentiate(h_report, known_r);

        // Add the known_w to the set, to make 100 known values.
        known_w_values.insert(known_w.compress());

        assert_eq!(known_w_values.len(), 100);

        let server1 = Server1Verify::new(known_w_values);
        let server2 = Server2Verify::new();

        let proof = server2.prove(&report, known_r, other_reports).unwrap();

        let result = server1.verify(&proof);

        assert_eq!(result.unwrap(), report);
    }
}
