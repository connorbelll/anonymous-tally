use anonymous_message_report_counting::domain_separate::domain32;
use anonymous_message_report_counting::group_operations::*;
use anonymous_message_report_counting::scheme_verification::*;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2_10::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::time::Duration;

const REPORT_DOMAIN: u8 = 0u8;

fn setupBatchSize(
    size: u32,
) -> (
    Server1Verify,
    Server2Verify,
    [u8; 32],
    RistrettoPoint,
    Scalar,
    Vec<WTPair>,
) {
    let mut known_w_t_pairs: HashMap<CompressedRistretto, CompressedRistretto> = HashMap::new();
    let mut other_reports: Vec<WTPair> = Vec::new();
    let sk_1 = random_scalar();
    let num_fake = size - 1;
    // 999 fake reports
    for _x in 0..num_fake {
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

    // Add the known_w to the set, to make 1000 known values.
    known_w_t_pairs.insert(known_w.compress(), known_t.compress());

    let vec_size = usize::try_from(size).expect("should fit in usize");
    assert_eq!(known_w_t_pairs.len(), vec_size);

    let server1 = Server1Verify::new(known_w_t_pairs);
    let server2 = Server2Verify::new();

    (server1, server2, report, known_t, known_r, other_reports)
}

fn setupVerifyOnly(size: u32) -> (Server1Verify, ReportVerification) {
    let (server1, server2, report, known_t, known_r, other_reports) = setupBatchSize(size);

    let proof = server2
        .prove(&report, known_t.compress(), known_r, other_reports)
        .unwrap();
    (server1, proof)
}

fn scheme(c: &mut Criterion) {
    let mut group = c.benchmark_group("Report Aggregation Scheme Verification");

    group.bench_function("Proof from S2 - size 100", |b| {
        b.iter_batched(
            || setupBatchSize(100),
            |(server1, server2, report, known_t, known_r, other_reports)| {
                let proof = server2
                    .prove(&report, known_t.compress(), known_r, other_reports)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Proof from S2 - size 1000", |b| {
        b.iter_batched(
            || setupBatchSize(1000),
            |(server1, server2, report, known_t, known_r, other_reports)| {
                let proof = server2
                    .prove(&report, known_t.compress(), known_r, other_reports)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Proof from S2 - size 10000", |b| {
        b.iter_batched(
            || setupBatchSize(10000),
            |(server1, server2, report, known_t, known_r, other_reports)| {
                let proof = server2
                    .prove(&report, known_t.compress(), known_r, other_reports)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Proof from S2 - size 100000", |b| {
        b.iter_batched(
            || setupBatchSize(100000),
            |(server1, server2, report, known_t, known_r, other_reports)| {
                let proof = server2
                    .prove(&report, known_t.compress(), known_r, other_reports)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Verification by S1 - size 100", |b| {
        b.iter_batched(
            || setupVerifyOnly(100),
            |(server1, proof)| {
                let result = server1.verify(&proof);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Verification by S1 - size 1000", |b| {
        b.iter_batched(
            || setupVerifyOnly(1000),
            |(server1, proof)| {
                let result = server1.verify(&proof);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Verification by S1 - size 10000", |b| {
        b.iter_batched(
            || setupVerifyOnly(10000),
            |(server1, proof)| {
                let result = server1.verify(&proof);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("Verification by S1 - size 100000", |b| {
        b.iter_batched(
            || setupVerifyOnly(100000),
            |(server1, proof)| {
                let result = server1.verify(&proof);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().measurement_time(Duration::from_secs(10)).confidence_level(0.9).sample_size(20);
    targets = scheme
}
criterion_main!(benches);
