
use kybelith::consensus::threat_detection::{ThreatLevel, evaluate_threat_level};
use kybelith::consensus::quantum_flex::QuantumFlexConsensus;
use kybelith::config::Settings;
use kybelith::consensus::{NetworkMetrics, NetworkCondition, ConsensusType};

use std::sync::Arc;
use std::time::Instant;

// Helper para criar métricas de rede com diferentes condições
fn create_test_network_metrics(
    message_loss_rate: f32,
    avg_latency: f32,
    suspicious_validators: usize,
    active_validators: usize,
    fork_count: usize
) -> NetworkMetrics {
    NetworkMetrics {
        message_loss_rate,
        average_latency_ms: avg_latency,
        connected_peers: 20,
        active_validators,
        suspicious_validators,
        orphan_rate: 0.0,
        fork_count,
        last_update: Instant::now(),
    }
}

#[test]
fn test_threat_level_evaluation() {
    // Condições normais - ameaça baixa
    let normal_metrics = create_test_network_metrics(0.01, 100.0, 0, 10, 0);
    assert_eq!(evaluate_threat_level(&normal_metrics), ThreatLevel::Low);
    
    // Perda moderada de mensagens - ameaça média
    let moderate_loss_metrics = create_test_network_metrics(0.15, 100.0, 0, 10, 0);
    assert_eq!(evaluate_threat_level(&moderate_loss_metrics), ThreatLevel::Medium);
    
    // Latência alta - ameaça média
    let high_latency_metrics = create_test_network_metrics(0.01, 1500.0, 0, 10, 0);
    assert_eq!(evaluate_threat_level(&high_latency_metrics), ThreatLevel::Medium);
    
    // Validadores suspeitos - ameaça média
    let suspicious_validators_metrics = create_test_network_metrics(0.01, 100.0, 2, 10, 0);
    assert_eq!(evaluate_threat_level(&suspicious_validators_metrics), ThreatLevel::Medium);
    
    // Muitos forks - ameaça média
    let many_forks_metrics = create_test_network_metrics(0.01, 100.0, 0, 10, 3);
    assert_eq!(evaluate_threat_level(&many_forks_metrics), ThreatLevel::Medium);
    
    // Perda severa de mensagens - ameaça alta
    let severe_loss_metrics = create_test_network_metrics(0.5, 100.0, 0, 10, 0);
    assert_eq!(evaluate_threat_level(&severe_loss_metrics), ThreatLevel::High);
    
    // Muitos validadores suspeitos - ameaça alta
    let many_suspicious_metrics = create_test_network_metrics(0.01, 100.0, 4, 10, 0);
    assert_eq!(evaluate_threat_level(&many_suspicious_metrics), ThreatLevel::High);
    
    // Combinação de problemas - ameaça alta
    let combined_issues_metrics = create_test_network_metrics(0.35, 2000.0, 3, 10, 6);
    assert_eq!(evaluate_threat_level(&combined_issues_metrics), ThreatLevel::High);
}

#[test]
fn test_network_condition_evaluation() {
    // Condições normais - rede estável
    let normal_metrics = create_test_network_metrics(0.01, 100.0, 0, 10, 0);
    assert_eq!(normal_metrics.network_condition(), NetworkCondition::Stable);
    
    // Latência moderada - rede degradada
    let moderate_latency_metrics = create_test_network_metrics(0.01, 1200.0, 0, 10, 0);
    assert_eq!(moderate_latency_metrics.network_condition(), NetworkCondition::Degraded);
    
    // Algumas perdas de mensagens - rede degradada
    let some_loss_metrics = create_test_network_metrics(0.15, 100.0, 0, 10, 0);
    assert_eq!(some_loss_metrics.network_condition(), NetworkCondition::Degraded);
    
    // Alguns forks - rede degradada
    let some_forks_metrics = create_test_network_metrics(0.01, 100.0, 0, 10, 3);
    assert_eq!(some_forks_metrics.network_condition(), NetworkCondition::Degraded);
    
    // Perdas severas - rede instável
    let severe_loss_metrics = create_test_network_metrics(0.35, 100.0, 0, 10, 0);
    assert_eq!(severe_loss_metrics.network_condition(), NetworkCondition::Unstable);
    
    // Muitos validadores suspeitos - rede instável
    let suspicious_validators_metrics = create_test_network_metrics(0.01, 100.0, 4, 10, 0);
    assert_eq!(suspicious_validators_metrics.network_condition(), NetworkCondition::Unstable);
}

// Este teste requer a existência do método config() para QuantumFlexConsensus
// e a capacidade de criar uma instância usando config e sem validadores
#[test]
fn test_consensus_adaptation() {
    // Criar configurações básicas
    let config = Arc::new(Settings::default());
    
    // Criar instância de consenso
    let consensus = QuantumFlexConsensus::new(Arc::clone(&config), Vec::new());
    
    // Testar adaptação para diferentes condições de rede
    
    // 1. Condições normais -> PoS
    let normal_metrics = create_test_network_metrics(0.01, 100.0, 0, 10, 0);
    consensus.update_network_metrics(normal_metrics);
    let adapted_type = consensus.evaluate_and_adapt();
    assert_eq!(adapted_type, ConsensusType::PoS);
    
    // 2. Rede degradada -> Híbrido
    let degraded_metrics = create_test_network_metrics(0.15, 1500.0, 1, 10, 2);
    consensus.update_network_metrics(degraded_metrics);
    let adapted_type = consensus.evaluate_and_adapt();
    assert_eq!(adapted_type, ConsensusType::Hybrid);
    
    // 3. Rede instável -> PBFT
    let unstable_metrics = create_test_network_metrics(0.35, 2000.0, 0, 10, 1);
    consensus.update_network_metrics(unstable_metrics);
    let adapted_type = consensus.evaluate_and_adapt();
    assert_eq!(adapted_type, ConsensusType::PBFT);
    
    // 4. Ameaça alta -> PBFT (mesmo com rede estável)
    let threat_metrics = create_test_network_metrics(0.01, 100.0, 4, 10, 0);
    consensus.update_network_metrics(threat_metrics);
    let adapted_type = consensus.evaluate_and_adapt();
    assert_eq!(adapted_type, ConsensusType::PBFT);
}