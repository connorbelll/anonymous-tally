use crate::domain_separate::domain32;
use crate::encrypt::{decrypt, encrypt, kgen, CT};
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

// Hash function domain separation bytes.
const REPORT_DOMAIN: u8 = 0u8;
const USER_HASH_DOMAIN: u8 = 1u8;
const SERVER_HASH_DOMAIN: u8 = 2u8;

/// The "tuple" structure of "pk1".
#[derive(Clone)]
pub struct PKOne {
    /// A public key paired with SKOne.rep.
    pub rep: RistrettoPoint,
    /// The public portion of a public key encryption scheme paired with SKOne.rd.
    pub rd: PKey<Public>,
}

/// The "tuple" structure of "sk1".
#[derive(Clone)]
pub struct SKOne {
    /// A private key paired with PKOne.rep.
    pub rep: Scalar,
    /// The private portion of a public key encryption scheme paired with PKOne.rd.
    pub rd: PKey<Private>,
}

/// All of the keys for the scheme.
pub struct RAKeys {
    /// A public key paired with sk1.
    pub pk1: PKOne,
    /// A public key paired with sk2.
    pub pk2: PKey<Public>,
    /// An oblivious PRF key held by Server 1.
    pub sk1: SKOne,
    /// The secret key paired with pk.
    pub sk2: PKey<Private>,
    /// A common backend key for MAC signing and verifying exponentiations.
    pub sk_s: [u8; 32],
}

/// Generate random keys for the scheme.
pub fn scheme_kgen() -> RAKeys {
    let sk1_rep = random_scalar();
    let pk1_rep = exponentiate(RISTRETTO_BASEPOINT_POINT, sk1_rep);

    let (sk1_rd, pk1_rd) = kgen();

    let (sk2, pk2) = kgen();

    let mut csprng = OsRng;
    let mut sk_s = [0u8; 32];
    csprng.fill_bytes(&mut sk_s);

    RAKeys {
        pk1: PKOne {
            rep: pk1_rep,
            rd: pk1_rd,
        },
        pk2: pk2,
        sk1: SKOne {
            rep: sk1_rep,
            rd: sk1_rd,
        },
        sk2: sk2,
        sk_s: sk_s,
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
    /// The encrypted (against PK1.rd) source tracking metadata.
    hd: CT,
}

/// The masked report and a PoK that the user used a consistent user_sk.
pub struct Phase1Output {
    /// The ID of the user.
    user_id: [u8; 16],
    /// The masked report point.
    w: CompressedRistretto,
    /// The masked report raised to the user_sk value.
    v: CompressedRistretto,
    /// A PoK that mask_user_sk was raised to the user_sk.
    pi_u: DlogProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PR {
    /// Masked PRF exponentiation (v^pk1).
    t: CompressedRistretto,
    /// MAC on the message of the oblivious PRF evaluation against the user key.
    sigma: [u8; 32],
}

pub struct ReportOutput {
    /// The ID of the report that was verified.
    report: [u8; 32],
    /// A point which should correspond uniquely to a (user_id, report) pair by scheme construction.
    dup_tag: RistrettoPoint,
    /// Hidden metadata that can be revealed by S1.
    hd: CT,
}

pub struct User {
    /// A PK for SKOne.rep computed by Server 1 and a public key to encrypt messages to Server 1.
    pk1: PKOne,
    /// PK for Server 2.
    pk2: PKey<Public>,
    /// Upper 127-bit key identifying this user.
    user_id: [u8; 16],
    /// A private-key Scalar to prevent server 1 from computing dup_tag on its own.
    user_sk: Scalar,
    /// A public key created by raising the basepoint to user_sk.
    user_pk: RistrettoPoint,
}

/// Server 1 in our scheme.
pub struct Server1 {
    /// Scalar to exponentiate the masked inputs to.
    sk1: SKOne,
    /// Verification key for proofs involving sk1.
    pk1: PKOne,
    /// MAC to sign the exponentiation.
    mac: BackendMAC,
    /// Mapping of users to user_pk.
    users: HashMap<[u8; 16], RistrettoPoint>,
}

/// Server 2 in our scheme.
pub struct Server2 {
    /// 256-bit MAC key for verifying exponentiations.
    sk2: PKey<Private>,
    /// MAC to verify the signature on the exponentiation from Server 1.
    mac: BackendMAC,
}

impl User {
    pub fn new(
        pk1: PKOne,
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
    pub fn report(&self, report: [u8; 32], server1: &Server1) -> Result<CT, &str> {
        let (r, phase1_output) = self.report_phase1(report);
        let (report_pt, pi_s) = self
            .invoke_phase2(report, r, server1, &phase1_output)
            .expect("Unable to interact with Server 1.");

        self.verify_exponentiation(&report_pt, &phase1_output, &pi_s)
            .expect("Failed to verify Server 1 exponentiation.");

        Ok(self.report_phase3(&report_pt, server1))
    }

    /// Returns the pre-report by hiding "report" with a random scalar, converting the report to a group
    /// element, and retrieving:
    /// 1) the server-side exponentiation of the masked report and
    /// 2) a MAC tag of the statement of the exponentiaiton
    /// from Server 1.
    pub fn report_phase1(&self, report: [u8; 32]) -> (Scalar, Phase1Output) {
        let r = random_scalar();
        let hash_report = hash_to_point(&domain32(REPORT_DOMAIN, report));
        let w = exponentiate(hash_report, r);
        let v = exponentiate(w, self.user_sk);
        let pi_u = prove_dlog(
            USER_HASH_DOMAIN,
            &w,
            &RISTRETTO_BASEPOINT_POINT,
            &self.user_sk,
            &v,
            &self.user_pk,
        );
        (
            r,
            Phase1Output {
                user_id: self.user_id,
                w: w.compress(),
                v: v.compress(),
                pi_u: pi_u,
            },
        )
    }

    pub fn invoke_phase2(
        &self,
        report: [u8; 32],
        r: Scalar,
        server1: &Server1,
        phase1_output: &Phase1Output,
    ) -> Result<(ReportPT, DlogProof), &str> {
        let (pr, pi_s) = server1
            .report_phase2(phase1_output)
            .expect("Unable to interact with Server 1");
        let bytes = [7u8; 160];
        let vec_bytes = bytes.to_vec();
        let hd: CT = encrypt(&self.pk1.rd, &vec_bytes);
        Ok((
            ReportPT {
                report: report,
                r: r,
                pr: pr,
                hd: hd.try_into().expect("could not create 'hd'"),
            },
            pi_s,
        ))
    }

    pub fn verify_exponentiation(
        &self,
        pt: &ReportPT,
        phase1_output: &Phase1Output,
        pi_s: &DlogProof,
    ) -> Result<(), &str> {
        let v = phase1_output.v.decompress().unwrap();
        if !verify_dlog(
            SERVER_HASH_DOMAIN,
            &v,
            &RISTRETTO_BASEPOINT_POINT,
            &pt.pr
                .t
                .decompress()
                .expect("Could not uncompress the PRF evaluation."),
            &self.pk1.rep,
            pi_s,
        ) {
            return Err("Server 1 did not prove that they exponentiated to sk1.");
        }

        Ok(())
    }

    /// Returns a ciphertext of the Report plain text encrypted using pk2.
    pub fn report_phase3(&self, pt: &ReportPT, server1: &Server1) -> CT {
        let encoded: Vec<u8> = bincode::serialize(&pt).unwrap();
        encrypt(&self.pk2, &encoded)
    }
}

impl Server1 {
    pub fn new(pk1: PKOne, sk1: SKOne, sk_s: [u8; 32]) -> Server1 {
        let mac = BackendMAC::new(sk_s);
        let users = HashMap::new();
        Server1 {
            pk1: pk1,
            sk1: sk1,
            mac: mac,
            users: users,
        }
    }

    /// Provides an oblivious PRF evaluation of the input using a user-specific key.
    /// In a real system, there would be additional authentication that the user ID
    /// belongs to the reporting user.
    fn report_phase2(&self, phase1_output: &Phase1Output) -> Result<(PR, DlogProof), &str> {
        let w = phase1_output.w.decompress().unwrap();
        let v = phase1_output.v.decompress().unwrap();
        let user_pk = self
            .users
            .get(&phase1_output.user_id)
            .expect("User is not registered.");
        if !verify_dlog(
            USER_HASH_DOMAIN,
            &w,
            &RISTRETTO_BASEPOINT_POINT,
            &v,
            &user_pk,
            &phase1_output.pi_u,
        ) {
            return Err("w was not properly exponentiated to user_sk");
        }

        let t = exponentiate(v, self.sk1.rep);

        let pi_s = prove_dlog(
            SERVER_HASH_DOMAIN,
            &v,
            &RISTRETTO_BASEPOINT_POINT,
            &self.sk1.rep,
            &t,
            &self.pk1.rep,
        );

        // RistrettoPoints can change representation when they go through compression, but
        // their compressed form will always produce the canonical form, so to guarantee a
        // consistent statement, we compress and decompress the points before formatting.
        let statement = format!("{:?} :pk1: {:?}", w, t.compress().decompress().unwrap());

        // Sign the statement so that Server 2 can later verify the exponentiation.
        let sigma = self.mac.sign(&statement.into_bytes());
        Ok((
            PR {
                t: t.compress(),
                sigma: sigma,
            },
            pi_s,
        ))
    }

    /// Decrypts the hidden metadata for a report.
    fn reveal(&self, ct: &CT) -> Vec<u8> {
        decrypt(&self.sk1.rd, ct)
    }

    fn register_new_user(&mut self, uid: &[u8; 16], user_pk: RistrettoPoint) {
        self.users.insert(*uid, user_pk);
    }
}

impl Server2 {
    pub fn new(sk2: PKey<Private>, sk_s: [u8; 32]) -> Server2 {
        let mac = BackendMAC::new(sk_s);
        Server2 { sk2: sk2, mac: mac }
    }

    pub fn verify(&self, ct: &CT) -> Result<ReportOutput, &'static str> {
        let decrypted = decrypt(&self.sk2, ct);
        let report_pt: ReportPT = bincode::deserialize(&decrypted[..]).unwrap();

        let hash_report = hash_to_point(&domain32(REPORT_DOMAIN, report_pt.report));
        let w_prime = exponentiate(hash_report, report_pt.r);
        let t = report_pt.pr.t;

        // Similarly here, compress and decompress the points to make sure they're in their
        // canonical form.
        let statement = format!(
            "{:?} :pk1: {:?}",
            w_prime.compress().decompress().unwrap(),
            t.decompress().unwrap()
        );
        let sigma = report_pt.pr.sigma;

        self.mac
            .verify(&statement.into_bytes(), &sigma)
            .expect("Unable to verify report");

        let dup_tag = exponentiate_inverse(t.decompress().unwrap(), report_pt.r);

        Ok(ReportOutput {
            report: report_pt.report,
            dup_tag: dup_tag,
            hd: report_pt.hd,
        })
    }
}

/// Returns a correctly configured user against an honest Server 1.
pub fn register_new_user(
    pk1: PKOne,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    server1: &mut Server1,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    server1.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which can have a different user_pk which is unrelated to user_sk (to try and trick Server 1 into submitting a non-dupliate report).
fn register_new_user_bad_sk(
    pk1: PKOne,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    user_pk: RistrettoPoint,
    server1: &mut Server1,
) -> User {
    server1.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which assigns a different pk1 than the one that Server 1 provides (to test invalidation of Server 1's exponentiation).
fn register_new_user_bad_pk1(
    pk1: PKOne,
    pk2: PKey<Public>,
    uid: [u8; 16],
    user_sk: Scalar,
    server1: &mut Server1,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    server1.register_new_user(&uid, user_pk);
    User::new(pk1, pk2, uid, user_sk, user_pk)
}

/// Returns a new user which assigns a different UID than the one that one registered with (to test invalidation of the user's exponentiation).
fn register_new_user_bad_uid(
    pk1: PKOne,
    pk2: PKey<Public>,
    uid: [u8; 16],
    bad_uid: [u8; 16],
    user_sk: Scalar,
    server1: &mut Server1,
) -> User {
    let user_pk = exponentiate(RISTRETTO_BASEPOINT_POINT, user_sk);
    server1.register_new_user(&uid, user_pk);
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

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user = register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

        let (r, phase1_output) = user.report_phase1(report);

        assert_eq!(
            phase1_output.w.decompress().unwrap(),
            exponentiate(hash_to_point(&domain32(REPORT_DOMAIN, report)), r)
        );
    }

    #[test]
    fn report_returns_ct() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user = register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

        let (r, phase1_output) = user.report_phase1(report);

        let (report_pt, _proof) = user
            .invoke_phase2(report, r, &server1, &phase1_output)
            .unwrap();

        let report = user.report_phase3(&report_pt, &server1);

        // Currently, the encryption is 256 bytes long.
        assert_eq!(report.encrypted.len(), 608);
    }

    #[test]
    fn report_decrypts_verifies() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user = register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);
        let server2 = Server2::new(keys.sk2, keys.sk_s);

        let ct = user.report(report, &server1).unwrap();

        let report_output = server2.verify(&ct).unwrap();

        assert_eq!(report_output.report, [1u8; 32]);

        let expected_rd = [7u8; 160];

        let rd = server1.reveal(&report_output.hd);

        assert_eq!(rd, expected_rd);
    }

    #[test]
    #[should_panic(expected = "User is not registered.")]
    fn report_panics_when_bad_uid() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];
        let bad_uid = [1u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user = register_new_user_bad_uid(
            keys.pk1.clone(),
            keys.pk2,
            uid,
            bad_uid,
            user_sk,
            &mut server1,
        );

        let (r, phase1_output) = user.report_phase1(report);

        user.invoke_phase2(report, r, &server1, &phase1_output)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "w was not properly exponentiated to user_sk")]
    fn report_panics_when_user_sk_proof_bad() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let user_pk = hash_to_point(&[37u8; 32]);
        let user = register_new_user_bad_sk(
            keys.pk1.clone(),
            keys.pk2,
            uid,
            user_sk,
            user_pk,
            &mut server1,
        );

        user.report(report, &server1).unwrap();
    }

    #[test]
    fn report_panics_when_pk1_proof_bad() {
        let keys = scheme_kgen();
        let uid = [0u8; 16];

        let report = [1u8; 32];
        let user_sk = random_scalar();

        let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
        let bad_pk_1 = hash_to_point(&[38u8; 32]);
        let user = register_new_user_bad_pk1(
            PKOne {
                rep: bad_pk_1,
                rd: keys.pk1.rd,
            },
            keys.pk2,
            uid,
            user_sk,
            &mut server1,
        );

        assert_panics!(
            user.report(report, &server1),
            includes("Server 1 did not prove that they exponentiated to sk1."),
            includes("Failed to verify Server 1 exponentiation.")
        )
    }
}
