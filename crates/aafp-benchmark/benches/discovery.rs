#![allow(deprecated)]

use aafp_discovery::capability_dht::CapabilityDht;
use aafp_identity::agent_record::AgentRecord;
use aafp_identity::AgentKeypair;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_dht_put(c: &mut Criterion) {
    c.bench_function("dht_put", |b| {
        b.iter_with_setup(
            || {
                let mut dht = CapabilityDht::new();
                let kp = AgentKeypair::generate();
                (dht, kp)
            },
            |(mut dht, kp)| {
                let record = AgentRecord::new(
                    &kp,
                    vec!["inference".into()],
                    vec!["quic://1.2.3.4:4433".into()],
                );
                dht.put(record).unwrap();
            },
        );
    });
}

fn bench_dht_get(c: &mut Criterion) {
    let mut dht = CapabilityDht::new();
    for _ in 0..100 {
        let kp = AgentKeypair::generate();
        let record = AgentRecord::new(
            &kp,
            vec!["inference".into()],
            vec!["quic://1.2.3.4:4433".into()],
        );
        dht.put(record).unwrap();
    }
    c.bench_function("dht_get_100_agents", |b| {
        b.iter(|| dht.get("inference"));
    });
}

fn bench_agent_record_create(c: &mut Criterion) {
    c.bench_function("agent_record_create", |b| {
        b.iter_with_setup(
            || AgentKeypair::generate(),
            |kp| {
                AgentRecord::new(
                    &kp,
                    vec!["inference".into(), "translation".into()],
                    vec!["quic://1.2.3.4:4433".into()],
                )
            },
        );
    });
}

fn bench_agent_record_verify(c: &mut Criterion) {
    let kp = AgentKeypair::generate();
    let record = AgentRecord::new(
        &kp,
        vec!["inference".into()],
        vec!["quic://1.2.3.4:4433".into()],
    );
    c.bench_function("agent_record_verify", |b| {
        b.iter(|| record.verify());
    });
}

criterion_group!(
    benches,
    bench_dht_put,
    bench_dht_get,
    bench_agent_record_create,
    bench_agent_record_verify,
);
criterion_main!(benches);
