use anonymous_message_report_counting::group_operations::*;
use anonymous_message_report_counting::scheme::*;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2_10::{Digest, Sha256};
use std::time::Duration;

fn scheme(c: &mut Criterion) {
    let mut group = c.benchmark_group("Report Aggregation Scheme");

    group.bench_function("Report from byte_array", |b| {
        b.iter_batched(
            || {
                // The Report metadata takes 160 bytes, so for a 1KB plaintext we would have 1,184 bytes
                // as input to the hash function.
                let mut report_in = [0u8; 1184];
                let mut csprng = OsRng;
                csprng.fill_bytes(&mut report_in);

                report_in
            },
            |report_in| {
                // Measure the amount of time to go from a 1,184 byte pt and fd to a deterministic report identifier.
                let mut hasher = Sha256::new();

                hasher.update(report_in);

                hasher.finalize();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Platform Initialization", |b| {
        b.iter_batched(
            || {},
            |()| {
                let keys = scheme_kgen();

                PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                VERIFY::new(keys.sk2, keys.sk3);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("User Registration", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);

                let prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);

                (keys, uid, prfs)
            },
            |(keys, uid, mut prfs)| {
                let user_sk = random_scalar();
                register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("client create a mask", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                (user, report)
            },
            |(user, report)| {
                user.report_phase1(report);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("PRF/S verify proof and exponentiate", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                let (r, mask) = user.report_phase1(report);

                (user, report, r, prfs, mask)
            },
            |(user, report, r, prfs, mask)| {
                user.invoke_phase2(report, r, &prfs, &mask).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Client verify proof", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                let (r, mask) = user.report_phase1(report);
                let (report_pt, proof) = user.invoke_phase2(report, r, &prfs, &mask).unwrap();

                (user, report_pt, proof, mask)
            },
            |(user, report_pt, proof, mask)| {
                user.verify_exponentiation(&report_pt, &mask, &proof)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Client encrypts", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                let (r, mask) = user.report_phase1(report);
                let (report_pt, _proof) = user.invoke_phase2(report, r, &prfs, &mask).unwrap();

                (user, report_pt, prfs)
            },
            |(user, report_pt, prfs)| {
                user.report_phase3(&report_pt, &prfs);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Full Report time", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                (user, report, prfs)
            },
            |(user, report, prfs)| {
                user.report(report, &prfs).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Verify time", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut prfs = PRFS::new(keys.pk1, keys.sk1, keys.sk3);
                let verify = VERIFY::new(keys.sk2, keys.sk3);
                let user = register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut prfs);

                let ct = user.report(report, &prfs).unwrap();

                (verify, ct)
            },
            |(verify, ct)| {
                verify.verify(&ct).unwrap();
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
