// Tests which should fail if we regress on bits transmitted over the wire.
#[cfg(test)]
mod tests {
    use crate::group_operations::*;
    use crate::prove_dlog::*;
    use crate::scheme::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
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
}
