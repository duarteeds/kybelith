use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,    // Ameaça baixa
    Medium, // Ameaça média
    High,   // Ameaça alta
}

/// Tipos de consenso suportados pelo sistema QuantumFlex
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusType {
    /// Prova de Participação (Proof of Stake)
    PoS,

    /// Tolerância a Falhas Bizantinas Prática
    PBFT,

    /// Modo híbrido combinando características de PoS e PBFT
    Hybrid,

    /// Modo adaptativo que alterna entre os outros com base em condições da rede
    Adaptive,
}

impl fmt::Display for ConsensusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusType::PoS => write!(f, "PoS"),
            ConsensusType::PBFT => write!(f, "PBFT"),
            ConsensusType::Hybrid => write!(f, "Hybrid"),
            ConsensusType::Adaptive => write!(f, "Adaptive"),
        }
    }
}

impl ConsensusType {
    /// Converte uma string para o tipo de consenso correspondente
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "POS" => Ok(ConsensusType::PoS),
            "PBFT" => Ok(ConsensusType::PBFT),
            "HYBRID" => Ok(ConsensusType::Hybrid),
            "ADAPTIVE" => Ok(ConsensusType::Adaptive),
            _ => Err(format!("Tipo de consenso desconhecido: {}", s)),
        }
    }
}

/// Representa o estado atual do sistema de consenso
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// O tipo de consenso atualmente em uso
    pub consensus_type: ConsensusType,

    /// Quando ocorreu a última adaptação do tipo de consenso
    pub last_adaptation: Instant,

    /// Altura do bloco atual
    pub current_block_height: u64,

    /// ID do validador atual (se estiver na fase de proposta)
    pub current_proposer: Option<String>,

    /// Época atual do consenso
    pub current_epoch: u64,

    /// Status do consenso para o bloco atual
    pub status: ConsensusStatus,
}

impl ConsensusState {
    /// Cria um novo estado de consenso com o tipo especificado
    pub fn new(consensus_type: ConsensusType) -> Self {
        Self {
            consensus_type,
            last_adaptation: Instant::now(),
            current_block_height: 0,
            current_proposer: None,
            current_epoch: 0,
            status: ConsensusStatus::Idle,
        }
    }

    /// Verifica se é hora de considerar uma adaptação no tipo de consenso
    pub fn should_adapt(&self, adaptation_interval: Duration) -> bool {
        self.last_adaptation.elapsed() >= adaptation_interval
    }

    /// Atualiza o tipo de consenso e marca o tempo da adaptação
    pub fn adapt_to(&mut self, new_type: ConsensusType) {
        if self.consensus_type != new_type {
            self.consensus_type = new_type;
            self.last_adaptation = Instant::now();
        }
    }
}

/// Status atual do processo de consenso
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStatus {
    /// Aguardando início do próximo round
    Idle,

    /// Selecionando um proposer para o próximo bloco
    SelectingProposer,

    /// Aguardando proposta de bloco
    WaitingForProposal,

    /// Verificando uma proposta recebida
    VerifyingProposal,

    /// Votando em uma proposta
    Voting,

    /// Contando votos
    CountingVotes,

    /// Finalizando um bloco
    Finalizing,

    /// Erro no processo de consenso
    Error,
}

/// Condição da rede com base em análise de métricas
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCondition {
    /// Rede operando de forma estável
    Stable,

    /// Rede com alguma instabilidade, mas funcional
    Degraded,

    /// Rede com problemas significativos
    Unstable,
}

/// Métricas da rede usadas para avaliar condições e ameaças
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Taxa de mensagens perdidas (0.0 - 1.0)
    pub message_loss_rate: f32,

    /// Latência média da rede em milissegundos
    pub average_latency_ms: f32,

    /// Número de peers conectados
    pub connected_peers: usize,

    /// Número de validadores ativos
    pub active_validators: usize,

    /// Número de validadores suspeitos (comportamento anômalo)
    pub suspicious_validators: usize,

    /// Taxa de blocos órfãos recentes
    pub orphan_rate: f32,

    /// Número de fork competitivos detectados
    pub fork_count: usize,

    /// Tempo desde a última atualização das métricas
    pub last_update: Instant,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            message_loss_rate: 0.0,
            average_latency_ms: 0.0,
            connected_peers: 0,
            active_validators: 0,
            suspicious_validators: 0,
            orphan_rate: 0.0,
            fork_count: 0,
            last_update: Instant::now(),
        }
    }
}

impl NetworkMetrics {
    /// Avalia a condição atual da rede com base nas métricas
    pub fn network_condition(&self) -> NetworkCondition {
        // Alta perda de mensagens ou muitos validadores suspeitos indica problemas
        if self.message_loss_rate > 0.3
            || self.suspicious_validators > self.active_validators / 3
            || self.orphan_rate > 0.2
        {
            return NetworkCondition::Unstable;
        }

        // Alguma degradação, mas não crítica
        if self.message_loss_rate > 0.1 || self.average_latency_ms > 1000.0 || self.fork_count > 2 {
            return NetworkCondition::Degraded;
        }

        // Rede operando normalmente
        NetworkCondition::Stable
    }
}

/// Resultado de uma decisão de consenso
#[derive(Debug, Clone)]
pub enum ConsensusDecision {
    /// Bloco aceito com hash especificado
    BlockAccepted {
        block_hash: String,
        block_height: u64,
    },

    /// Bloco rejeitado com motivo
    BlockRejected { reason: String },

    /// Round de consenso falhou
    RoundFailed { reason: String },
}

/// Erros que podem ocorrer durante o processo de consenso
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Proposer inválido: {0}")]
    InvalidProposer(String),

    #[error("Bloco proposto inválido: {0}")]
    InvalidBlock(String),

    #[error("Validação falhou: {0}")]
    ValidationFailed(String),

    #[error("Timeout de consenso")]
    ConsensusTimeout,

    #[error("Votos insuficientes: requerido {required}, recebido {received}")]
    InsufficientVotes { required: usize, received: usize },

    #[error("Configuração inválida: {0}")]
    ConfigurationError(String),

    #[error("Erro interno: {0}")]
    InternalError(String),
}

/// Resultado da verificação de uma proposta
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proposta válida e aceita
    Valid,

    /// Proposta inválida com motivo
    Invalid(String),

    /// Incapaz de verificar no momento (ex: falta de informação)
    Indeterminate,
}
