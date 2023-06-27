use anonymous_message_report_counting::domain_separate::domain32;
use anonymous_message_report_counting::group_operations::*;
use anonymous_message_report_counting::scheme_verification::*;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2_10::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Duration;

const REPORT_DOMAIN: u8 = 0u8;

fn scheme(c: &mut Criterion) {
    let mut group = c.benchmark_group("Report Aggregation Scheme Verification");

    group.bench_function("Proof from S2", |b| {
        b.iter_batched(
            || {
                let mut known_w_values = HashSet::new();
                // 99 fake reports
                for _x in 0..99 {
                    known_w_values.insert(random_point().compress());
                }
                let other_reports: Vec<CompressedRistretto> =
                    known_w_values.clone().into_iter().collect();

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

                (server1, server2, report, known_r, other_reports)
            },
            |(server1, server2, report, known_r, other_reports)| {
                let proof = server2.prove(&report, known_r, other_reports).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Verification by S1", |b| {
        b.iter_batched(
            || {
                let mut known_w_values = HashSet::new();
                // 99 fake reports
                for _x in 0..99 {
                    known_w_values.insert(random_point().compress());
                }
                let other_reports: Vec<CompressedRistretto> =
                    known_w_values.clone().into_iter().collect();

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

                (server1, proof)
            },
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
    config = Criterion::default().measurement_time(Duration::from_secs(60)).confidence_level(0.95).sample_size(1000);
    targets = scheme
}
criterion_main!(benches);
