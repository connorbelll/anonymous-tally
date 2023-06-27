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

                Server1::new(keys.pk1, keys.sk1, keys.sk_s);
                Server2::new(keys.sk2, keys.sk_s);
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

                let server1 = Server1::new(keys.pk1.clone(), keys.sk1.clone(), keys.sk_s);

                (keys, uid, server1)
            },
            |(keys, uid, mut server1)| {
                let user_sk = random_scalar();
                register_new_user(keys.pk1, keys.pk2, uid, user_sk, &mut server1);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("client create a phase1_output", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let user = register_new_user(
                    keys.pk1.clone(),
                    keys.pk2.clone(),
                    uid,
                    user_sk,
                    &mut server1,
                );

                (user, report)
            },
            |(user, report)| {
                user.report_phase1(report);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("Server 1 verify proof and exponentiate", |b| {
        b.iter_batched(
            || {
                let keys = scheme_kgen();
                let mut uid = [0u8; 16];
                let mut report = [1u8; 32];

                let mut csprng = OsRng;
                csprng.fill_bytes(&mut uid);
                csprng.fill_bytes(&mut report);

                let user_sk = random_scalar();

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let user = register_new_user(
                    keys.pk1.clone(),
                    keys.pk2.clone(),
                    uid,
                    user_sk,
                    &mut server1,
                );

                let (r, phase1_output) = user.report_phase1(report);

                (user, report, r, server1, phase1_output)
            },
            |(user, report, r, server1, phase1_output)| {
                user.invoke_phase2(report, r, &server1, &phase1_output)
                    .unwrap();
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

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let user =
                    register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

                let (r, phase1_output) = user.report_phase1(report);
                let (report_pt, proof) = user
                    .invoke_phase2(report, r, &server1, &phase1_output)
                    .unwrap();

                (user, report_pt, proof, phase1_output)
            },
            |(user, report_pt, proof, phase1_output)| {
                user.verify_exponentiation(&report_pt, &phase1_output, &proof)
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

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let user =
                    register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

                let (r, phase1_output) = user.report_phase1(report);
                let (report_pt, _proof) = user
                    .invoke_phase2(report, r, &server1, &phase1_output)
                    .unwrap();

                (user, report_pt, server1)
            },
            |(user, report_pt, server1)| {
                user.report_phase3(&report_pt, &server1);
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

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let user =
                    register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

                (user, report, server1)
            },
            |(user, report, server1)| {
                user.report(report, &server1).unwrap();
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

                let mut server1 = Server1::new(keys.pk1.clone(), keys.sk1, keys.sk_s);
                let server2 = Server2::new(keys.sk2, keys.sk_s);
                let user =
                    register_new_user(keys.pk1.clone(), keys.pk2, uid, user_sk, &mut server1);

                let ct = user.report(report, &server1).unwrap();

                (server2, ct)
            },
            |(server2, ct)| {
                server2.verify(&ct).unwrap();
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
