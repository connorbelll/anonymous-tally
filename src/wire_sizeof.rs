// Tests which should fail if we regress on bits transmitted over the wire.
#[cfg(test)]
mod tests {
    const REPORT_DOMAIN: u8 = 0u8;
    use crate::domain_separate::domain32;
    use crate::group_operations::*;
    use crate::prove_dlog::*;
    use crate::scheme::*;
    use crate::scheme_verification::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use rand::rngs::StdRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use std::mem::size_of;

    #[test]
    fn sizeof_mask() {
        // Phase 1 Output (including PoK) takes up 176 bytes (1,408 bits).
        assert_eq!(size_of::<Phase1Output>(), 176);
    }

    #[test]
    fn sizeof_pr_and_proof() {
        // PR and Proof returned by Server 1 take up 160 bytes (1,280 bits) total.
        assert_eq!(size_of::<PR>(), 64);
        assert_eq!(size_of::<DlogProof>(), 96);
    }

    #[test]
    fn sizeof_ct() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user = register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

        let ct = user.report(report, &server1).unwrap();

        // CT takes up 256 bytes (2048 bits)
        assert_eq!(ct.encrypted.len(), 608);
    }

    #[test]
    fn sizeof_compressedristretto() {
        // 32 bytes to store a dup_tag.
        assert_eq!(size_of::<CompressedRistretto>(), 32);
    }

    #[test]
    fn sizeof_verificationproof() {
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

        let server1 = Server1Verify::new(known_w_t_pairs);
        let server2 = Server2Verify::new();

        let proof = server2
            .prove(&report, known_t.compress(), known_r, other_reports)
            .unwrap();

        let encoded: Vec<u8> = bincode::serialize(&proof).unwrap();

        assert_eq!(encoded.len(), 19312);
    }
}
