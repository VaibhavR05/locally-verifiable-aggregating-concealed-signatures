use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

#[path = "datasets/mod.rs"]
mod datasets;

fn benchmark_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate");

    for &size in datasets::Dataset::sizes() {
        let dataset = datasets::Dataset::load(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("concealed_signatures", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    dataset.scheme().aggregate_concealed_signatures(
                        black_box(&dataset.verification_keys()[..size]),
                        black_box(&dataset.concealed_signatures()[..size]),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("local_opening", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    dataset.scheme().local_aggregate_opening(
                        black_box(dataset.aggregate()),
                        black_box(&dataset.verification_keys()[..size]),
                        black_box(&dataset.concealed_signatures()[..size]),
                        0,
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_aggregate);
criterion_main!(benches);
