use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[path = "datasets/mod.rs"]
mod datasets;

fn benchmark_bls(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls");
    let dataset = datasets::Dataset::default();
    let mut keygen_rng = ark_std::test_rng();

    group.bench_function("key_gen", |b| {
        b.iter(|| dataset.scheme().key_gen(black_box(&mut keygen_rng)));
    });
    group.bench_function("sign", |b| {
        b.iter(|| {
            dataset
                .scheme()
                .sign(
                    black_box(&dataset.signing_keys()[0]),
                    black_box(&dataset.messages()[0]),
                )
                .expect("benchmark signing should succeed")
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            dataset
                .scheme()
                .verify(
                    black_box(&dataset.verification_keys()[0]),
                    black_box(&dataset.messages()[0]),
                    black_box(&dataset.signatures()[0]),
                )
                .expect("benchmark verification should succeed")
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_bls);
criterion_main!(benches);
