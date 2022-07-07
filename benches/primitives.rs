use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::arithmetic::Field;
use mimc_halo2::mimc::primitives::{mimc5_hash_pallas, mimc5_encrypt_pallas, mimc5_hash_vesta, mimc5_encrypt_vesta};
use rand::rngs::OsRng;
use pasta_curves::{pallas, vesta};


fn bench_primitives(c: &mut Criterion) {
    let rng = OsRng;
    {
        let mut group = c.benchmark_group("MiMC");

        let mut pallas_message = pallas::Base::random(rng);

        group.bench_function("pallas_hash", |b| {
            b.iter(|| {
                mimc5_hash_pallas(&mut pallas_message)
            })
        });

        pallas_message = pallas::Base::random(rng);
        let pallas_key = pallas::Base::random(rng);

        group.bench_function("pallas_encrypt", |b| {
            b.iter(|| {
                mimc5_encrypt_pallas(&mut pallas_message, pallas_key)
            })
        });

        let mut vesta_message = vesta::Base::random(rng);

        group.bench_function("vesta_hash", |b| {
            b.iter(|| {
                mimc5_hash_vesta(&mut vesta_message)
            })
        });

        vesta_message = vesta::Base::random(rng);
        let vesta_key = vesta::Base::random(rng);

        group.bench_function("vesta_encrypt", |b| {
            b.iter(|| {
                mimc5_encrypt_vesta(&mut vesta_message, vesta_key)
            })
        });
    }
}

criterion_group!(benches, bench_primitives);
criterion_main!(benches);
