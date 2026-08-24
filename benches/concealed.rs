use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[path = "datasets/mod.rs"]
mod datasets;

fn benchmark_concealed(c: &mut Criterion) {
    let mut group = c.benchmark_group("concealed");
    let dataset = datasets::Dataset::default();
    let mut conceal_rng = ark_std::test_rng();

    group.bench_function("csetup", |b| {
        b.iter(|| {
            dataset
                .scheme()
                .convert(
                    black_box(&dataset.verification_keys()[0]),
                    black_box(&dataset.messages()[0]),
                    black_box(&dataset.signatures()[0]),
                    black_box(&mut conceal_rng),
                )
                .expect("benchmark concealed parameter generation should succeed")
        });
    });

    group.bench_function("convert", |b| {
        b.iter(|| {
            dataset
                .scheme()
                .convert(
                    black_box(&dataset.verification_keys()[0]),
                    black_box(&dataset.messages()[0]),
                    black_box(&dataset.signatures()[0]),
                    black_box(&mut conceal_rng),
                )
                .expect("benchmark hashing should succeed")
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            dataset.scheme().verify_concealed(
                black_box(&dataset.concealed_signatures()[0]),
                black_box(&dataset.verification_keys()[0]),
            )
        });
    });
    group.bench_function("open", |b| {
        b.iter(|| {
            dataset
                .scheme()
                .open_concealed_signature(
                    black_box(&dataset.messages()[0]),
                    black_box(&dataset.concealed_signatures()[0]),
                    black_box(&dataset.auxiliary_data()[0]),
                )
                .expect("benchmark hashing should succeed")
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_concealed);
criterion_main!(benches);
