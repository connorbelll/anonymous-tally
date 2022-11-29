use crate::domain_separate::domain32;
use crate::encrypt::{decrypt, encrypt, kgen};
use crate::group_operations::{exponentiate, exponentiate_inverse, hash_to_point, random_scalar};
use crate::mac::BackendMAC;
use crate::prove_dlog::{prove_dlog, verify_dlog, DlogProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use openssl::pkey::{PKey, Private, Public};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const REPORT_DOMAIN: u8 = 0u8;
const USER_SK_DOMAIN: u8 = 1u8;
const PRFS_KU_DOMAIN: u8 = 2u8;

// All of the keys for the scheme.
pub struct RAKeys {
    // A public key paired with sk1.
    pub pk1: RistrettoPoint,
    // A public key paired with sk2.
    pub pk2: PKey<Public>,
    // A PRF key held by PRF/S.
    pub sk1: Scalar,
    // The secret key paired with pk.
    pub sk2: PKey<Private>,
    // A common backend key for MAC signing and verifying exponentiations.
    pub sk3: [u8; 32],
}

/// Generate random keys for the scheme.
pub fn scheme_kgen() -> RAKeys {
    let sk1 = random_scalar();
    let pk1 = exponentiate(RISTRETTO_BASEPOINT_POINT, sk1);

    let (sk2, pk2) = kgen();

    let mut csprng = OsRng;
    let mut sk3 = [0u8; 32];
    csprng.fill_bytes(&mut sk3);

    RAKeys {
        pk1: pk1,
        pk2: pk2,
        sk1: sk1,
        sk2: sk2,
        sk3: sk3,
    }
}

/// A successful result from the PreReport stage.

#[derive(Serialize, Deserialize, Debug)]
pub struct ReportPT {
    /// Bit-string report.
    report: [u8; 32],
    /// Random mask to use in oblivious PRF.
    r: Scalar,
    /// Response from Report Phase 2
    pr: PR,
}

/// The masked report and a PoK that the user used a consistent user_sk.
pub struct Mask {
    /// The ID of the user.
    user_id: [u8; 16],
    /// The masked report point.
    mask: CompressedRistretto,
    /// The masked report raised to the user_sk value.
    mask_user_sk: CompressedRistretto,
    /// A PoK that mask_user_sk was raised to the user_sk.
    proof: DlogProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PR {
    /// Masked PRF exponentiation (mask^k_u).
    eval: CompressedRistretto,
    /// MAC on the message of the oblivious PRF evaluation against the user key.
    sigma: [u8; 32],
}

pub struct ReportOutput {
    /// The ID of the report that was verified.
    report: [u8; 32],
    /// A point which should correspond uniquely to a (user_id, report) pair by scheme construction.
    dup_tag: RistrettoPoint,
}

pub struct User {
    /// A PK for sk1 computed by PRF/S.
    pk1: RistrettoPoint,
    /// PK for VERIFY, tbd the structure.
    pk2: PKey<Public>,
    /// Upper 127-bit key identifying this user.
    user_id: [u8; 16],
    /// A private-key Scalar to prevent server 1 from computing dup_tag on its own.
    user_sk: Scalar,
    /// A public key created by raising the basepoint to user_sk.
    user_pk: RistrettoPoint,
}

/// Server 1 in our scheme.
pub struct PRFS {
    /// Scalar to exponentiate the masked inputs to.
    sk1: Scalar,
    /// Verification key for proofs involving sk1.
    pk1: RistrettoPoint,
    /// MAC to sign the exponentiation.
    mac: BackendMAC,
    /// Mapping of users to user_pk.
    users: HashMap<[u8; 16], RistrettoPoint>,
}

/// Server 2 in our scheme.
pub struct VERIFY {
    /// 256-bit MAC key for verifying exponentiations.
    sk2: PKey<Private>,
    /// MAC to verify the signature on the exponentiation from PRF/S.
    mac: BackendMAC,
}

impl User {
    pub fn new(
        pk1: RistrettoPoint,
        pk2: PKey<Public>,
        user_id: [u8; 16],
        user_sk: Scalar,
        user_pk: RistrettoPoint,
    ) -> User {
        User {
            pk1: pk1,
            pk2: pk2,
            user_id: user_id,
            user_sk: user_sk,
            user_pk: user_pk,
        }
    }

    /// Runs the full Report algorithm and returns the resulting ciphertext.
    pub fn report(&self, report: [u8; 32], prfs: &PRFS) -> Result<Vec<u8>, &str> {
        let (r, mask) = self.report_phase1(report);
        let (report_pt, proof) = self
            .invoke_phase2(report, r, prfs, &mask)
            .expect("Unable to interact with PRF/S.");

        self.verify_exponentiation(&report_pt, &mask, &proof)
            .expect("Failed to verify PRF/S exponentiation.");

        Ok(self.report_phase3(&report_pt, prfs))
    }

    /// Returns the pre-report by hiding "report" with a random scalar, converting the report to a group
    /// element, and retrieiving:
    /// 1) the server-side exponentiation of the masked report and
    /// 2) a MAC tag of the statement of the exponentiaiton
    /// from PRF/S.
    pub fn report_phase1(&self, report: [u8; 32]) -> (Scalar, Mask) {
        let r = random_scalar();
        let hash_report = hash_to_point(&domain32(REPORT_DOMAIN, report));
        let mask = exponentiate(hash_report, r);
        let mask_user_sk = exponentiate(mask, self.user_sk);
        let proof = prove_dlog(
            USER_SK_DOMAIN,
            &mask,
            &RISTRETTO_BASEPOINT_POINT,
            &self.user_sk,
            &mask_user_sk,
            &self.user_pk,
        );
        (
            r,
            Mask {
                user_id: self.user_id,
                mask: mask.compress(),
                mask_user_sk: mask_user_sk.compress(),
                proof: proof,
            },
        )
    }

    pub fn invoke_phase2(
        &self,
        report: [u8; 32],
        r: Scalar,
        prfs: &PRFS,
        mask: &Mask,
    ) -> Result<(ReportPT, DlogProof), &str> {
        let (pr, proof) = prfs
            .report_phase2(mask)
            .expect("Unable to interact with PRF/S");
        Ok((
            ReportPT {
                report: report,
                r: r,
                pr: pr,
            },
            proof,
        ))
    }

    pub fn verify_exponentiation(
        &self,
        pt: &ReportPT,
        mask: &Mask,
        proof: &DlogProof,
    ) -> Result<(), &str> {
        let mask_user_sk = mask.mask_user_sk.decompress().unwrap();
        if !verify_dlog(
            PRFS_KU_DOMAIN,
            &mask_user_sk,
            &RISTRETTO_BASEPOINT_POINT,
            &pt.pr
                .eval
                .decompress()
                .expect("Could not uncompress the PRF evaluation."),
            &self.pk1,
            proof,
        ) {
            return Err("PRF/S did not prove that they exponentiated to k_u.");
        }

        Ok(())
    }

    /// Returns a ciphertext of the Report plain text encrypted using pk2.
    pub fn report_phase3(&self, pt: &ReportPT, prfs: &PRFS) -> Vec<u8> {
        let encoded: Vec<u8> = bincode::serialize(&pt).unwrap();
        encrypt(&self.pk2, &encoded)
    }
}

impl PRFS {
    pub fn new(pk1: RistrettoPoint, sk1: Scalar, sk3: [u8; 32]) -> PRFS {
        let mac = BackendMAC::new(sk3);
        let users = HashMap::new();
        PRFS {
            pk1: pk1,
            sk1: sk1,
            mac: mac,
            users: users,
        }
    }

    /// Provides an oblivious PRF evaluation of the input using a user-specific key.
    /// In a real system, there would be additional authentication that the user ID
    /// belongs to the reporting user.
    fn report_phase2(&self, mask: &Mask) -> Result<(PR, DlogProof), &str> {
        let mask_decompressed = mask.mask.decompress().unwrap();
        let mask_user_sk = mask.mask_user_sk.decompress().unwrap();
        let user_pk = self
            .users
            .get(&mask.user_id)
            .expect("User is not registered.");
        if !verify_dlog(
            USER_SK_DOMAIN,
            &mask_decompressed,
            &RISTRETTO_BASEPOINT_POINT,
            &mask_user_sk,
            &user_pk,
            &mask.proof,
        ) {
            return Err("Mask was not properly exponentiated to user_sk");
        }

        let eval = exponentiate(mask_user_sk, self.sk1);

        let proof = prove_dlog(
            PRFS_KU_DOMAIN,
            &mask_user_sk,
            &RISTRETTO_BASEPOINT_POINT,
            &self.sk1,
            &eval,
            &self.pk1,
        );

        // RistrettoPoints can change representation when they go through compression, but
        // their compressed form will always produce the canonical form, so to guarantee a
        // consistent statement, we compress and decompress the points before formatting.
        let statement = format!(
            "{:?} :k_u: {:?}",
            mask_decompressed,
            eval.compress().decompress().unwrap()
        );

        // Sign the statement so that VERIFY can later verify the exponentiation.
        let sigma = self.mac.sign(&statement.into_bytes());
        Ok((
            PR {
                eval: eval.compress(),
                sigma: sigma,
            },
            proof,
        ))
    }

    fn register_new_user(&mut self, uid: &[u8; 16], user_pk: RistrettoPoint) {
        self.users.insert(*uid, user_pk);
    }
}

impl VERIFY {
    pub fn new(sk2: PKey<Private>, sk3: [u8; 32]) -> VERIFY {
        let mac = BackendMAC::new(sk3);
        VERIFY { sk2: sk2, mac: mac }
    }

    pub fn verify(&self, ct: &Vec<u8>) -> Result<ReportOutput, &'static str> {
        let decrypted = decrypt(&self.sk2, ct);
        let report_pt: ReportPT = bincode::deserialize(&decrypted[..]).unwrap();

        let hash_report = hash_to_point(&domain32(REPORT_DOMAIN, report_pt.report));
        let mask = exponentiate(hash_report, report_pt.r);
        let mask_exponentiated = report_pt.pr.eval;

        // Similarly here, compress and decompress the points to make sure they're in their
        // canonical form.
        let statement = format!(
            "{:?} :k_u: {:?}",
            mask.compress().decompress().unwrap(),
            report_pt.pr.eval.decompress().unwrap()
        );
        let tag = report_pt.pr.sigma;

        self.mac
            .verify(&statement.into_bytes(), &tag)
            .expect("Unable to verify report");

        let dup_tag = exponentiate_inverse(mask_exponentiated.decompress().unwrap(), report_pt.r);

        Ok(ReportOutput {
            report: report_pt.report,
            dup_tag: dup_tag,
        })
    }
}

/// Returns a correctly configured user against an honest PRF/S.
pub fn register_new_user(
    pk1: RistrettoPoint,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    prfs: &mut PRFS,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    prfs.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which can have a different user_pk which is unrelated to user_sk (to try and trick PRF/S into submitting a non-dupliate report).
fn register_new_user_bad_sk(
    pk1: RistrettoPoint,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    user_pk: RistrettoPoint,
    prfs: &mut PRFS,
) -> User {
    prfs.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which assigns a different k_u_pk than the one that PRF/S provides (to test invalidation of PRF/S exponentiation).
fn register_new_user_bad_k_u_pk(
    pk1: RistrettoPoint,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    prfs: &mut PRFS,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    prfs.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which assigns a different k_u_pk than the one that PRF/S provides (to test invalidation of PRF/S exponentiation).
fn register_new_user_bad_uid(
    pk1: RistrettoPoint,
    pk2: PKey<Public>,
    uid: [u8; 16],
    bad_uid: [u8; 16],
    user_sk: Scalar,
    prfs: &mut PRFS,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    prfs.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, bad_uid, user_sk, user_pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cool_asserts::assert_panics;

    #[test]
    fn pre_report_completes() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

        let (r, mask) = user.report_phase1(report);

        assert_eq!(
            mask.mask.decompress().unwrap(),
            exponentiate(hash_to_point(&domain32(REPORT_DOMAIN, report)), r)
        );
    }

    #[test]
    fn report_returns_ct() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

        let (r, mask) = user.report_phase1(report);

        let (report_pt, _proof) = user.invoke_phase2(report, r, &prfs, &mask).unwrap();

        let report = user.report_phase3(&report_pt, &prfs);

        // Currently, the encryption is 256 bytes long.
        assert_eq!(report.len(), 256);
    }

    #[test]
    fn report_decrypts_verifies() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);
        let verify = VERIFY::new(keys.sk2, keys.sk3);

        let ct = user.report(report, &prfs).unwrap();

        let report_output = verify.verify(&ct).unwrap();

        assert_eq!(report_output.report, [1u8; 32]);
    }

    #[test]
    #[should_panic(expected = "User is not registered.")]
    fn report_panics_when_bad_uid() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];
        let bad_uid = [1u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user = register_new_user_bad_uid(keys.pk1, keys.pk2, uid, bad_uid, user_sk, &mut prfs);

        let (r, mask) = user.report_phase1(report);

        user.invoke_phase2(report, r, &prfs, &mask).unwrap();
    }

    #[test]
    #[should_panic(expected = "Mask was not properly exponentiated to user_sk")]
    fn report_panics_when_user_sk_proof_bad() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let user_pk = hash_to_point(&[37u8; 32]);
        let user = register_new_user_bad_sk(keys.pk1, keys.pk2, uid, user_sk, user_pk, &mut prfs);

        user.report(report, &prfs).unwrap();
    }

    #[test]
    fn report_panics_when_k_u_proof_bad() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
        let bad_pk_1 = hash_to_point(&[38u8; 32]);
        let user = register_new_user_bad_k_u_pk(bad_pk_1, keys.pk2, uid, user_sk, &mut prfs);

        assert_panics!(
            user.report(report, &prfs),
            includes("PRF/S did not prove that they exponentiated to k_u."),
            includes("Failed to verify PRF/S exponentiation.")
        )
    }
}
