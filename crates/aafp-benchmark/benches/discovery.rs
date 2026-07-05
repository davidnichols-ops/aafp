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

// --- DHT Routing Benchmarks (Track R5) ---

use aafp_crypto::{MlDsa65, SignatureScheme};
use aafp_discovery::dht_router::{DhtRouter, DhtRouterConfig, InMemoryDhtNetwork};
use aafp_identity::identity_v1::{AgentRecord as AgentRecordV1, CapabilityDescriptor};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn make_bench_record(seed: u8, capabilities: Vec<&str>) -> AgentRecordV1 {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let (pk, sk) = MlDsa65::keypair_from_seed(&seed_bytes);
    let now = 1700000000u64;
    let mut record = AgentRecordV1::new(
        &pk.0,
        capabilities
            .iter()
            .map(|c| CapabilityDescriptor::new(*c))
            .collect(),
        vec![format!("/ip4/127.0.0.1/tcp/{}", 4000 + seed as u16)],
        now,
        now + 86400,
        1,
    );
    record.sign(&sk);
    record
}

fn setup_dht_network(
    n: usize,
) -> (
    Arc<InMemoryDhtNetwork>,
    Vec<Arc<DhtRouter>>,
    Vec<AgentRecordV1>,
) {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let network = Arc::new(InMemoryDhtNetwork::new());
        let records: Vec<AgentRecordV1> = (0..n)
            .map(|i| make_bench_record((i + 1) as u8, vec![&format!("cap{}", i % 10)]))
            .collect();
        let routers: Vec<Arc<DhtRouter>> = records
            .iter()
            .map(|r| {
                Arc::new(
                    DhtRouter::with_config(
                        r.agent_id.clone(),
                        network.clone(),
                        DhtRouterConfig::default(),
                    )
                    .with_time_provider(|| 1700000000),
                )
            })
            .collect();

        for (i, router) in routers.iter().enumerate() {
            router.set_own_record(records[i].clone()).await;
            network.register(router.clone()).await;
        }

        // Build mesh
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    routers[i].add_peer(records[j].clone()).await;
                }
            }
        }

        // Each node announces
        for (i, router) in routers.iter().enumerate() {
            router.announce(records[i].clone()).await;
        }

        (network, routers, records)
    })
}

fn bench_dht_routing_10_nodes(c: &mut Criterion) {
    let (_, routers, _) = setup_dht_network(10);
    let rt = Runtime::new().unwrap();

    c.bench_function("dht_routing_10_nodes", |b| {
        b.iter(|| {
            rt.block_on(async {
                routers[0].invalidate_all_cache().await;
                routers[0].find_peers("cap5", 10).await
            })
        });
    });
}

fn bench_dht_routing_50_nodes(c: &mut Criterion) {
    let (_, routers, _) = setup_dht_network(50);
    let rt = Runtime::new().unwrap();

    c.bench_function("dht_routing_50_nodes", |b| {
        b.iter(|| {
            rt.block_on(async {
                routers[0].invalidate_all_cache().await;
                routers[0].find_peers("cap5", 10).await
            })
        });
    });
}

fn bench_dht_routing_100_nodes(c: &mut Criterion) {
    let (_, routers, _) = setup_dht_network(100);
    let rt = Runtime::new().unwrap();

    c.bench_function("dht_routing_100_nodes", |b| {
        b.iter(|| {
            rt.block_on(async {
                routers[0].invalidate_all_cache().await;
                routers[0].find_peers("cap5", 10).await
            })
        });
    });
}

criterion_group!(
    benches,
    bench_dht_put,
    bench_dht_get,
    bench_agent_record_create,
    bench_agent_record_verify,
    bench_dht_routing_10_nodes,
    bench_dht_routing_50_nodes,
    bench_dht_routing_100_nodes,
);
criterion_main!(benches);
