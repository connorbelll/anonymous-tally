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
        // Mask (including PoK) takes up 176 bytes (1,408 bits).
        assert_eq!(size_of::<Mask>(), 176);
    }

    #[test]
    fn sizeof_pr_and_proof() {
        // PR and Proof returned by PRFS take up 160 bytes (1,280 bits) total.
        assert_eq!(size_of::<PR>(), 64);
        assert_eq!(size_of::<DlogProof>(), 96);
    }

    #[test]
    fn sizeof_ct() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

        let ct = user.report(report, &prfs).unwrap();

        // CT takes up 256 bytes (2048 bits)
        assert_eq!(ct.len(), 256);
    }

    #[test]
    fn sizeof_compressedristretto() {
        // 32 bytes to store a dup_tag.
        assert_eq!(size_of::<CompressedRistretto>(), 32);
    }
}
