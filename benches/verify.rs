use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[path = "datasets/mod.rs"]
mod datasets;

fn benchmark_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    let dataset = datasets::Dataset::default();
    let local_opening = dataset.scheme().local_aggregate_opening(
        dataset.aggregate(),
        dataset.verification_keys(),
        dataset.concealed_signatures(),
        0,
    );

    group.bench_function("aggregate", |b| {
        b.iter(|| {
            dataset.scheme().verify_aggregate(
                black_box(dataset.verification_keys()),
                black_box(dataset.aggregate()),
            )
        });
    });
    group.bench_function("local", |b| {
        b.iter(|| {
            dataset.scheme().local_verify(
                black_box(&dataset.verification_keys()[0]),
                black_box(dataset.aggregate()),
                black_box(&local_opening),
                black_box(&dataset.concealed_signatures()[0]),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_verify);
criterion_main!(benches);
