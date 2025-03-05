use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// Estrutura principal de configuração contendo todos os parâmetros do sistema
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// Configurações do nó
    pub node: NodeConfig,

    /// Configurações de rede P2P
    pub p2p: P2PConfig,

    /// Configurações do sistema de consenso
    pub consensus: ConsensusConfig,

    /// Configurações de segurança quântica
    pub quantum_security: QuantumSecurityConfig,

    /// Configurações para interoperabilidade com outras blockchains
    pub interoperability: InteroperabilityConfig,
}

/// Configurações específicas do nó
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// ID do nó na rede
    pub node_id: String,

    /// Diretório de dados para armazenamento
    pub data_dir: String,

    /// Nível de log (error, warn, info, debug, trace)
    pub log_level: String,

    /// Flag indicando se o nó é um validador
    pub is_validator: bool,
}

/// Configurações relacionadas à rede P2P
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PConfig {
    /// Endereço de escuta (IP:porta)
    pub listen_address: String,

    /// Máximo de conexões de entrada permitidas
    pub max_incoming_connections: u32,

    /// Máximo de conexões de saída que o nó vai manter
    pub max_outgoing_connections: u32,

    /// Lista de nós bootstrap para descoberta inicial de peers
    pub bootstrap_nodes: Vec<String>,

    /// Tempo de timeout para conexões (em segundos)
    pub connection_timeout_sec: u64,

    /// Frequência de ping para manter conexões vivas (em segundos)
    pub ping_interval_sec: u64,

    /// Habilita proteção contra ataques Sybil
    pub enable_sybil_protection: bool,

    /// Intervalo para tentar descobrir novos pares (em segundos)
    pub peer_discovery_interval_sec: u64,
}

/// Configurações do sistema de consenso QuantumFlex
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Tipo inicial de consenso (POS, PBFT, HYBRID, ADAPTIVE)
    pub initial_consensus_type: String,

    /// Intervalo de blocos em segundos
    pub block_interval_sec: u64,

    /// Duração de uma época em número de blocos
    pub epoch_length: u64,

    /// Número mínimo de validadores necessários
    pub min_validators: u32,

    /// Porcentagem mínima de stake para se tornar validador (0-100)
    pub min_stake_percentage: f32,

    /// Tempo máximo para formar consenso antes de timeout (em segundos)
    pub consensus_timeout_sec: u64,

    /// Número de blocos para finalidade (não pode ser revertido após)
    pub finality_blocks: u64,

    /// Percentual de votação necessário para finalidade (0-100)
    pub finality_threshold_percentage: f32,

    /// Quanto tempo esperar para adaptação de consenso (em blocos)
    pub adaptation_interval_blocks: u64,

    /// Habilita sistema de reputação para validadores
    pub enable_reputation_system: bool,
}

/// Configurações de segurança quântica
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuantumSecurityConfig {
    /// Variante do Kyber (ex: 512, 768, 1024)
    pub kyber_variant: u32,

    /// Variante do Dilithium (ex: 2, 3, 5)
    pub dilithium_variant: u32,

    /// Frequência de rotação de chaves em número de blocos
    pub key_rotation_interval: u64,

    /// Habilita proteção contra side-channel attacks
    pub enable_side_channel_protection: bool,

    /// Habilita proteção contra timing attacks
    pub enable_timing_attack_protection: bool,
}

/// Configurações para interoperabilidade
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteroperabilityConfig {
    /// Habilita pontes para outras blockchains
    pub enable_bridges: bool,

    /// Lista de blockchains com as quais interagir
    pub supported_blockchains: Vec<String>,

    /// Intervalo para sincronização com outras blockchains (em segundos)
    pub bridge_sync_interval_sec: u64,

    /// Número mínimo de confirmações antes de aceitar transações de outras chains
    pub min_external_confirmations: u64,
}

impl Settings {
    /// Carrega as configurações de um arquivo
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut file = File::open(path)
            .map_err(|e| format!("Falha ao abrir arquivo de configuração: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Falha ao ler arquivo de configuração: {}", e))?;

        serde_json::from_str(&contents)
            .map_err(|e| format!("Falha ao deserializar configuração: {}", e))
    }

    /// Cria configurações padrão
    pub fn default() -> Self {
        Self {
            node: NodeConfig {
                node_id: uuid::Uuid::new_v4().to_string(),
                data_dir: "./data".to_string(),
                log_level: "info".to_string(),
                is_validator: false,
            },
            p2p: P2PConfig {
                listen_address: "0.0.0.0:8000".to_string(),
                max_incoming_connections: 100,
                max_outgoing_connections: 30,
                bootstrap_nodes: vec![
                    "bootstrap1.quantum-blockchain.example:8000".to_string(),
                    "bootstrap2.quantum-blockchain.example:8000".to_string(),
                ],
                connection_timeout_sec: 10,
                ping_interval_sec: 30,
                enable_sybil_protection: true,
                peer_discovery_interval_sec: 300,
            },
            consensus: ConsensusConfig {
                initial_consensus_type: "ADAPTIVE".to_string(),
                block_interval_sec: 10,
                epoch_length: 100,
                min_validators: 4,
                min_stake_percentage: 5.0,
                consensus_timeout_sec: 30,
                finality_blocks: 20,
                finality_threshold_percentage: 67.0,
                adaptation_interval_blocks: 50,
                enable_reputation_system: true,
            },
            quantum_security: QuantumSecurityConfig {
                kyber_variant: 512,
                dilithium_variant: 5,
                key_rotation_interval: 10000,
                enable_side_channel_protection: true,
                enable_timing_attack_protection: true,
            },
            interoperability: InteroperabilityConfig {
                enable_bridges: true,
                supported_blockchains: vec![
                    "ethereum".to_string(),
                    "polkadot".to_string(),
                    "solana".to_string(),
                ],
                bridge_sync_interval_sec: 60,
                min_external_confirmations: 20,
            },
        }
    }

    /// Salva as configurações em um arquivo
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Falha ao serializar configuração: {}", e))?;

        std::fs::write(path, contents)
            .map_err(|e| format!("Falha ao escrever arquivo de configuração: {}", e))
    }

    /// Obtém o timeout de conexão como Duration
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.p2p.connection_timeout_sec)
    }

    /// Obtém o intervalo de ping como Duration
    pub fn ping_interval(&self) -> Duration {
        Duration::from_secs(self.p2p.ping_interval_sec)
    }

    /// Obtém o intervalo de blocos como Duration
    pub fn block_interval(&self) -> Duration {
        Duration::from_secs(self.consensus.block_interval_sec)
    }
}
