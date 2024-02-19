use crate::domain_separate::domain32;
use crate::group_operations::{
    divide, exponentiate, exponentiate_inverse, hash_to_point, multiply, random_point,
    random_scalar,
};
use crate::prove_dlog_or::produce_challenge;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Hash function domain separation bytes.
const REPORT_DOMAIN: u8 = 0u8;
const OR_CHALLENGE_DOMAIN: u8 = 3u8;

/// A successful result from the PreReport stage.
#[derive(Serialize, Deserialize, Debug)]
pub struct ReportVerification {
    /// Bit-string report.
    report: [u8; 32],
    /// The duptag which equals t^(1/r)
    duptag: CompressedRistretto,
    /// Array of w values, one of which corresponds to the report.
    w_values: Vec<CompressedRistretto>,
    /// Array of t values, each paired with the w in the same position.
    t_values: Vec<CompressedRistretto>,
    /// RHS coefficients for the H(Rep) -> w proof, additional inputs to the challenge.
    y1_values: Vec<CompressedRistretto>,
    /// RHS coefficients for the dup_tag -> t proof, additional inputs to the challenge.
    y2_values: Vec<CompressedRistretto>,
    /// The exponents for the LHS terms.
    z_values: Vec<Scalar>,
    /// The chosen challenges, which must all add up to the produced challenge, C.
    c_values: Vec<Scalar>,
}

// A value of W and T observed by S1.
#[derive(Clone)]
pub struct WTPair {
    /// The w (i.e. H(rep)^r) value observed by S1.
    pub w_value: CompressedRistretto,
    /// The t value (i.e. w ^ (sk_u * sk_1)) observed by S1.
    pub t_value: CompressedRistretto,
}

/// Server 1 (restricted to verification) in our scheme.
pub struct Server1Verify {
    /// Mapping of users to user_pk.
    seen_w_t_pairs: HashMap<CompressedRistretto, CompressedRistretto>,
}

/// Server 2 (restricted to verification) in our scheme.
pub struct Server2Verify {}

impl Server1Verify {
    pub fn new(seen_w_t_pairs: HashMap<CompressedRistretto, CompressedRistretto>) -> Server1Verify {
        Server1Verify {
            seen_w_t_pairs: seen_w_t_pairs,
        }
    }

    /// Processes a verification proof and returns either the report identifier that has now been counted
    /// or an error.
    pub fn verify(&self, verification: &ReportVerification) -> Result<[u8; 32], &'static str> {
        // Check that we've seen all of the w values before.
        for x in 0..verification.w_values.len() {
            let w = verification.w_values[x];
            let t = verification.t_values[x];
            if !self.seen_w_t_pairs.contains_key(&w) {
                return Err("Unseen w value");
            }
            if self.seen_w_t_pairs.get(&w) != Some(&t) {
                return Err("T value does not go with W value");
            }
        }

        // Check that each of the individual proofs checks out:
        // H(rep) ^ z_i == y_i * w ^ c_i
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, verification.report));

        for x in 0..verification.z_values.len() {
            let z = verification.z_values[x];
            let y1 = verification.y1_values[x];
            let y2 = verification.y2_values[x];
            let w = verification.w_values[x];
            let t = verification.t_values[x];
            let c = verification.c_values[x];
            let duptag = verification
                .duptag
                .decompress()
                .expect("could not decompress duptag");

            let lhs = exponentiate(h_report, z);
            let rhs = multiply(
                y1.decompress().expect("Could not decompress y1 value"),
                exponentiate(w.decompress().expect("Could not decompress w value"), c),
            );

            if lhs.compress() != rhs.compress() {
                return Err("Found an invalid proof");
            }

            // Now verify that the DLOG between duptag and T also verifies.
            let lhs2 = exponentiate(duptag, z);
            let rhs2 = multiply(
                y2.decompress().expect("could not decompress y2 value"),
                exponentiate(t.decompress().expect("could not decompress t value"), c),
            );

            if lhs2.compress() != rhs2.compress() {
                return Err("Found an invalid proof");
            }
        }

        // Check that Sum(c_i) = c, the overall challenge.
        let c = produce_challenge(
            OR_CHALLENGE_DOMAIN,
            verification.report,
            verification.duptag,
            &verification.w_values,
            &verification.t_values,
            &verification.y1_values,
            &verification.y2_values,
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
        t: CompressedRistretto,
        r: Scalar,
        other_reports: Vec<WTPair>,
    ) -> Result<ReportVerification, &'static str> {
        // Compute H(rep) for the base of the LHS (common to all proofs).
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, *report));

        // Compute the randomness for the "real" proof so we can compute the y value.
        let some_randomness = random_scalar();
        let some_randomness_pk = exponentiate(h_report, some_randomness);
        let real_w = exponentiate(h_report, r);
        let real_duptag =
            exponentiate_inverse(t.decompress().expect("Unable to decompress point"), r);
        let real_duptag_pk = exponentiate(real_duptag, some_randomness);

        // Choose k - 1 random values for z and c and compute the y that makes it true.
        let mut z_values: Vec<Scalar> = Vec::new();
        let mut c_values: Vec<Scalar> = Vec::new();
        let mut y1_values: Vec<CompressedRistretto> = Vec::new();
        let mut y2_values: Vec<CompressedRistretto> = Vec::new();
        for pair in other_reports.iter() {
            let x = pair.w_value;
            let t = pair.t_value;
            let z = random_scalar();
            let c = random_scalar();

            let lhs = exponentiate(h_report, z);
            let partial_rhs = exponentiate(x.decompress().expect("Unable to decompress point"), c);
            let y = divide(lhs, partial_rhs);

            let lhs2 = exponentiate(real_duptag, z);
            let partial_rhs2 = exponentiate(t.decompress().expect("Unable to decompress point"), c);
            let y2 = divide(lhs2, partial_rhs2);

            z_values.push(z);
            c_values.push(c);
            y1_values.push(y.compress());
            y2_values.push(y2.compress());
        }

        // Put the "real" w and y values in the lists.
        let mut w_t_pairs = other_reports.clone();
        w_t_pairs.push(WTPair {
            w_value: real_w.compress(),
            t_value: t,
        });
        y1_values.push(some_randomness_pk.compress());
        y2_values.push(real_duptag_pk.compress());

        // TODO: we need to shuffle the lists (all with identical shuffling) so that the verifier
        // doesn't know which proof is real (and this *must* happen before we generate the challenge).

        let w_values = w_t_pairs.clone().into_iter().map(|i| i.w_value).collect();
        let t_values = w_t_pairs.clone().into_iter().map(|i| i.t_value).collect();
        // Compute the real challenge.
        let mut c = produce_challenge(
            OR_CHALLENGE_DOMAIN,
            *report,
            real_duptag.compress(),
            &w_values,
            &t_values,
            &y1_values,
            &y2_values,
        );
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
            duptag: real_duptag.compress(),
            w_values: w_values,
            t_values: t_values,
            y1_values: y1_values,
            y2_values: y2_values,
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
        let mut known_w_t_pairs: HashMap<CompressedRistretto, CompressedRistretto> = HashMap::new();
        let mut other_reports: Vec<WTPair> = Vec::new();
        let sk_1 = random_scalar();
        // 99 fake reports
        for _x in 0..99 {
            let sk_u = random_scalar();
            let fake_w = random_point();
            let fake_t = exponentiate(exponentiate(fake_w, sk_u), sk_1);
            known_w_t_pairs.insert(fake_w.compress(), fake_t.compress());
            other_reports.push(WTPair {
                w_value: fake_w.compress(),
                t_value: fake_t.compress(),
            });
        }

        // Randomly generate a report, then choose an r value to generate a known "w".
        let mut csprng = StdRng::from_entropy();
        let mut report = [0u8; 32];
        csprng.fill_bytes(&mut report);
        let h_report = hash_to_point(&domain32(REPORT_DOMAIN, report));
        let known_r = random_scalar();
        let known_w = exponentiate(h_report, known_r);
        let sk_u = random_scalar();
        let known_t = exponentiate(exponentiate(known_w, sk_u), sk_1);

        // Add the known_w to the set, to make 100 known values.
        known_w_t_pairs.insert(known_w.compress(), known_t.compress());

        assert_eq!(known_w_t_pairs.len(), 100);

        let server1 = Server1Verify::new(known_w_t_pairs);
        let server2 = Server2Verify::new();

        let proof = server2
            .prove(&report, known_t.compress(), known_r, other_reports)
            .unwrap();

        let result = server1.verify(&proof);

        assert_eq!(result.unwrap(), report);
    }
}
