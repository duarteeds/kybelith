use criterion::{criterion_group, criterion_main, Criterion};
use crate::p2p::network::NetworkManager;
use crate::p2p::message::Message;
use crate::p2p::types::{NodeId, MessageType};

fn bench_message_routing(c: &mut Criterion) {
    let network = NetworkManager::new("127.0.0.1:8080");
    let message = Message {
        sender: "node1".to_string(),
        message_type: MessageType::BlockProposal,
        payload: vec![1, 2, 3],
    };

    c.bench_function("message_routing", |b| {
        b.iter(|| network.send_message(&"node2".to_string(), message.clone()))
    });
}

fn bench_broadcast(c: &mut Criterion) {
    let network = NetworkManager::new("127.0.0.1:8080");
    let message = Message {
        sender: "node1".to_string(),
        message_type: MessageType::BlockProposal,
        payload: vec![1, 2, 3],
    };

    c.bench_function("broadcast", |b| {
        b.iter(|| network.broadcast_message(message.clone()))
    });
}

criterion_group!(benches, bench_message_routing, bench_broadcast);
criterion_main!(benches);