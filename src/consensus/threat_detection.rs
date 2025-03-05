use crate::consensus::types::NetworkMetrics;
use log::{info, warn};

/// Níveis de ameaça para o sistema de consenso
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    /// Nenhuma ameaça significativa detectada
    Low,

    /// Possíveis ameaças que requerem atenção
    Medium,

    /// Ameaças graves que requerem adaptação imediata
    High,
}

/// Tipos específicos de ameaças que podem ser detectadas
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    /// Possível ataque de negação de serviço
    DenialOfService,

    /// Comportamento bizantino (ações maliciosas) de validadores
    ByzantineBehavior,

    /// Provável ataque Sybil (múltiplas identidades)
    SybilAttack,

    /// Tentativa de isolar nós (ataque eclipse)
    EclipseAttack,

    /// Tentativa de reorganização longa da blockchain
    LongRangeAttack,

    /// Ataques de timing
    TimingAttack,

    /// Degradação natural da rede (não maliciosa)
    NetworkDegradation,
}

/// Detalhes de uma ameaça detectada
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// Tipo específico de ameaça
    pub threat_type: ThreatType,

    /// Nível de severidade da ameaça
    pub level: ThreatLevel,

    /// Descrição da ameaça e evidências
    pub description: String,

    /// Possíveis validadores envolvidos (se aplicável)
    pub involved_validators: Vec<String>,

    /// Timestamp da detecção
    pub detected_at: std::time::Instant,
}

/// Avalia o nível de ameaça com base nas métricas de rede
pub fn evaluate_threat_level(metrics: &NetworkMetrics) -> ThreatLevel {
    // Indicadores de alto nível de ameaça
    if metrics.suspicious_validators > metrics.active_validators / 3 ||  // Mais de 1/3 de validadores suspeitos
       metrics.message_loss_rate > 0.4 ||                              // Perda de mensagens muito alta
       metrics.fork_count > 5
    {
        // Muitos forks competitivos
        warn!("Nível de ameaça ALTO detectado! Validadores suspeitos: {}/{}, Perda de mensagens: {:.1}%, Forks: {}",
             metrics.suspicious_validators, metrics.active_validators,
             metrics.message_loss_rate * 100.0, metrics.fork_count);
        return ThreatLevel::High;
    }

    // Indicadores de nível médio de ameaça
    if metrics.suspicious_validators > 0 ||                            // Qualquer validador suspeito
       metrics.message_loss_rate > 0.1 ||                              // Perda de mensagens moderada
       metrics.average_latency_ms > 1000.0 ||                          // Latência alta
       metrics.fork_count > 2
    {
        // Alguns forks competitivos
        info!("Nível de ameaça MÉDIO detectado. Validadores suspeitos: {}, Latência: {:.1}ms, Forks: {}",
             metrics.suspicious_validators, metrics.average_latency_ms, metrics.fork_count);
        return ThreatLevel::Medium;
    }

    // Nenhum indicador de ameaça
    ThreatLevel::Low
}

/// Detecta ameaças específicas com base nas métricas de rede
pub fn detect_threats(
    metrics: &NetworkMetrics,
    validator_behaviors: &[(String, f32)],
) -> Vec<ThreatInfo> {
    let mut threats = Vec::new();

    // Detecta possível DoS
    if metrics.message_loss_rate > 0.3 || metrics.average_latency_ms > 2000.0 {
        threats.push(ThreatInfo {
            threat_type: ThreatType::DenialOfService,
            level: if metrics.message_loss_rate > 0.5 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            },
            description: format!(
                "Possível ataque DoS. Perda de mensagens: {:.1}%, Latência: {:.1}ms",
                metrics.message_loss_rate * 100.0,
                metrics.average_latency_ms
            ),
            involved_validators: Vec::new(),
            detected_at: std::time::Instant::now(),
        });
    }

    // Detecta comportamento bizantino de validadores
    let suspicious_validators: Vec<String> = validator_behaviors
        .iter()
        .filter(|(_, score)| *score < 30.0) // Validadores com reputação muito baixa
        .map(|(id, _)| id.clone())
        .collect();

    if !suspicious_validators.is_empty() {
        threats.push(ThreatInfo {
            threat_type: ThreatType::ByzantineBehavior,
            level: if suspicious_validators.len() > metrics.active_validators / 3 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            },
            description: format!(
                "{} validadores exibindo comportamento suspeito",
                suspicious_validators.len()
            ),
            involved_validators: suspicious_validators,
            detected_at: std::time::Instant::now(),
        });
    }

    // Detecta possível ataque Sybil
    // (Múltiplos validadores aparecendo da mesma sub-rede, por exemplo)
    // Esta é uma implementação simplificada - na prática, precisaria analisar endereços IP, etc.
    if metrics.active_validators > 20 && metrics.connected_peers < metrics.active_validators / 2 {
        threats.push(ThreatInfo {
            threat_type: ThreatType::SybilAttack,
            level: ThreatLevel::Medium,
            description: format!(
                "Possível ataque Sybil. {} validadores mas apenas {} peers conectados",
                metrics.active_validators, metrics.connected_peers
            ),
            involved_validators: Vec::new(),
            detected_at: std::time::Instant::now(),
        });
    }

    // Detecta possível ataque de reorganização
    if metrics.fork_count > 3 && metrics.orphan_rate > 0.15 {
        threats.push(ThreatInfo {
            threat_type: ThreatType::LongRangeAttack,
            level: if metrics.fork_count > 5 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            },
            description: format!(
                "Possível tentativa de reorganização. {} forks, taxa de órfãos: {:.1}%",
                metrics.fork_count,
                metrics.orphan_rate * 100.0
            ),
            involved_validators: Vec::new(),
            detected_at: std::time::Instant::now(),
        });
    }

    threats
}

/// Recomenda adaptações com base nas ameaças detectadas
pub fn recommend_adaptations(threats: &[ThreatInfo]) -> Vec<AdaptationAction> {
    let mut actions = Vec::new();

    for threat in threats {
        match threat.threat_type {
            ThreatType::DenialOfService | ThreatType::NetworkDegradation => {
                // Para problemas de rede, recomenda mudar para PBFT que é mais tolerante a latência
                actions.push(AdaptationAction::SwitchConsensusTo(ConsensusMode::PBFT));
                actions.push(AdaptationAction::IncreaseForkResistance);
            }
            ThreatType::ByzantineBehavior => {
                // Para comportamento bizantino, também recomenda PBFT que é BFT por design
                actions.push(AdaptationAction::SwitchConsensusTo(ConsensusMode::PBFT));

                // Se for grave, também recomenda banimento temporário dos validadores envolvidos
                if threat.level == ThreatLevel::High {
                    for validator in &threat.involved_validators {
                        actions.push(AdaptationAction::TemporaryBanValidator(validator.clone()));
                    }
                }
            }
            ThreatType::SybilAttack => {
                // Para ataques Sybil, recomenda aumento nas exigências de stake
                actions.push(AdaptationAction::IncreaseMinimumStake);
                actions.push(AdaptationAction::EnhancePeerVerification);
            }
            ThreatType::EclipseAttack => {
                // Para ataques eclipse, recomenda diversificação de conexões
                actions.push(AdaptationAction::DiversifyConnections);
                actions.push(AdaptationAction::SwitchConsensusTo(ConsensusMode::PBFT));
            }
            ThreatType::LongRangeAttack => {
                // Para ataques de reorganização, aumenta requisitos de finalidade
                actions.push(AdaptationAction::IncreaseFinality);
                actions.push(AdaptationAction::SwitchConsensusTo(ConsensusMode::PBFT));
            }
            ThreatType::TimingAttack => {
                // Para ataques de timing, adiciona aleatoriedade e proteções
                actions.push(AdaptationAction::EnhanceTimingProtection);
            }
        }
    }

    // Remove duplicatas mantendo a ordem
    let mut unique_actions = Vec::new();
    for action in actions {
        if !unique_actions.contains(&action) {
            unique_actions.push(action);
        }
    }

    unique_actions
}

/// Tipo de consenso para recomendação de adaptação
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMode {
    PoS,
    PBFT,
    Hybrid,
}

/// Ações de adaptação recomendadas pelo sistema de detecção de ameaças
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptationAction {
    /// Mudar para um tipo específico de consenso
    SwitchConsensusTo(ConsensusMode),

    /// Aumentar temporariamente os requisitos de finalidade
    IncreaseFinality,

    /// Aumentar a resistência a forks
    IncreaseForkResistance,

    /// Aumentar o stake mínimo para validadores
    IncreaseMinimumStake,

    /// Melhorar verificação de peers
    EnhancePeerVerification,

    /// Diversificar conexões para evitar ataques eclipse
    DiversifyConnections,

    /// Banir temporariamente um validador específico
    TemporaryBanValidator(String),

    /// Melhorar proteções contra ataques de timing
    EnhanceTimingProtection,
}
