
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

/// Configuração para gerenciamento de épocas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Número de blocos em uma época
    pub epoch_length: u64,

    /// Tempo mínimo para uma época em segundos (se os blocos forem muito rápidos)
    pub min_epoch_time_secs: u64,

    /// Tempo máximo para uma época em segundos (se os blocos forem muito lentos)
    pub max_epoch_time_secs: u64,

    /// Atraso em blocos após o fim da época para aplicar mudanças
    pub activation_delay: u64,
}

impl EpochConfig {
    /// Cria uma nova configuração de época com valores razoáveis
    pub fn new(epoch_length: u64) -> Self {
        Self {
            epoch_length,
            min_epoch_time_secs: 3600,  // Mínimo 1 hora
            max_epoch_time_secs: 86400, // Máximo 1 dia
            activation_delay: 10,       // 10 blocos de atraso para ativação
        }
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self::new(100) // 100 blocos por época por padrão
    }
}

/// Informações sobre uma época específica
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    /// Número da época
    pub epoch_number: u64,

    /// Altura do bloco inicial da época
    pub start_block: u64,

    /// Altura do bloco final da época (estimado)
    pub end_block: u64,

    /// Quando a época começou
    pub start_time: chrono::DateTime<chrono::Utc>,

    /// Quando a época terminou (ou deve terminar)
    pub expected_end_time: chrono::DateTime<chrono::Utc>,

    /// Se a época já terminou
    pub is_completed: bool,

    /// Estatísticas da época
    pub stats: EpochStats,
}

/// Estatísticas coletadas durante uma época
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EpochStats {
    /// Número de blocos produzidos nesta época
    pub blocks_produced: u64,

    /// Número de blocos esperados com base no intervalo de bloco
    pub blocks_expected: u64,

    /// Taxa média de blocos perdidos
    pub block_miss_rate: f32,

    /// Tempo médio entre blocos em segundos
    pub avg_block_time_secs: f32,

    /// Número de transações processadas
    pub transactions_processed: u64,

    /// Número de validadores únicos que propuseram blocos
    pub unique_proposers: u64,

    /// Taxa de participação dos validadores (porcentagem)
    pub validator_participation: f32,

    pub proposers: HashSet<String>, // Track unique proposer IDs
}

/// Gerencia o ciclo de épocas para o sistema de consenso
#[derive(Debug)]
pub struct EpochManager {
    /// Configuração das épocas
    config: EpochConfig,

    /// Epoch atual
    current_epoch: u64,

    /// Início da época atual (altura do bloco)
    current_epoch_start: u64,

    /// Timestamp do início da época atual
    current_epoch_start_time: Instant,

    /// Histórico de épocas anteriores
    epoch_history: Vec<EpochInfo>,

    /// Estatísticas da época atual
    current_stats: EpochStats,
}

impl EpochManager {
    /// Cria um novo gerenciador de épocas
    pub fn new(config: EpochConfig) -> Self {
        Self {
            config,
            current_epoch: 0,
            current_epoch_start: 0,
            current_epoch_start_time: Instant::now(),
            epoch_history: Vec::new(),
            current_stats: EpochStats::default(),
        }
    }

    /// Atualiza o gerenciador com um novo bloco
    pub fn process_new_block(&mut self, block_height: u64) -> Option<EpochTransition> {
    // Atualiza estatísticas da época atual
    self.current_stats.blocks_produced += 1;  // Corrected from keys_produced

    if self.should_transition(block_height) {
        println!("Transição de época acionada no bloco {}", block_height);
        let transition = self.transition_to_new_epoch(block_height);
        return Some(transition);
    }
    None
}

    /// Verifica se é hora de transicionar para uma nova época
    fn should_transition(&self, block_height: u64) -> bool {
    let blocks_condition = block_height >= self.current_epoch_start + self.config.epoch_length;
    let min_time_condition = self.current_epoch_start_time.elapsed().as_secs() >= self.config.min_epoch_time_secs;
    let max_time_condition = self.current_epoch_start_time.elapsed().as_secs() >= self.config.max_epoch_time_secs;
    println!("blocks_condition: {}, min_time: {}, max_time: {}", blocks_condition, min_time_condition, max_time_condition);


    // Transiciona se atingiu o número de blocos e o tempo mínimo, ou se atingiu o tempo máximo
    (blocks_condition && min_time_condition) || max_time_condition
}

    /// Realiza a transição para uma nova época
  fn transition_to_new_epoch(&mut self, block_height: u64) -> EpochTransition {
    // Finaliza a época atual
    let completed_epoch = EpochInfo {
        epoch_number: self.current_epoch,
        start_block: self.current_epoch_start,
        end_block: block_height - 1,
        start_time: chrono::DateTime::from_timestamp(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - self.current_epoch_start_time.elapsed().as_secs()) as i64,
            0,
        )
        .unwrap_or_else(|| chrono::Utc::now()),
        expected_end_time: chrono::Utc::now(),
        is_completed: true,
        stats: self.current_stats.clone(),
    };

    // Adiciona ao histórico
    self.epoch_history.push(completed_epoch.clone()); // Garantir que o histórico é atualizado

    // Incrementa para a nova época
    self.current_epoch += 1;
    self.current_epoch_start = block_height;
    self.current_epoch_start_time = Instant::now();
    self.current_stats = EpochStats::default();

    // Cria o objeto de transição
    EpochTransition {
        previous_epoch: self.current_epoch - 1,
        new_epoch: self.current_epoch,
        transition_block: block_height,
        activation_block: block_height + self.config.activation_delay,
        previous_epoch_info: completed_epoch,
    }
}

    /// Obtém informações sobre a época atual
    pub fn current_epoch_info(&self) -> EpochInfo {
        EpochInfo {
            epoch_number: self.current_epoch,
            start_block: self.current_epoch_start,
            end_block: self.current_epoch_start + self.config.epoch_length - 1,
            start_time: chrono::DateTime::from_timestamp(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - self.current_epoch_start_time.elapsed().as_secs()) as i64,
                0,
            )
            .unwrap_or_else(|| chrono::Utc::now()),
            expected_end_time: chrono::Utc::now()
                + chrono::Duration::seconds(
                    (self.config.epoch_length - self.current_stats.blocks_produced) as i64
                        * self.config.max_epoch_time_secs as i64
                        / self.config.epoch_length as i64,
                ),
            is_completed: false,
            stats: self.current_stats.clone(),
        }
    }

    /// Obtém o número da época atual
    pub fn current_epoch_number(&self) -> u64 {
        self.current_epoch
    }

    /// Obtém o histórico de épocas anteriores
    pub fn epoch_history(&self) -> &[EpochInfo] {
        &self.epoch_history
    }

    /// Obtém a informação de uma época específica
    pub fn get_epoch_info(&self, epoch_number: u64) -> Option<&EpochInfo> {
        self.epoch_history
            .iter()
            .find(|e| e.epoch_number == epoch_number)
    }

    /// Registra uma transação processada na época atual
    pub fn record_transaction(&mut self) {
        self.current_stats.transactions_processed += 1;
    }

    /// Registra um proposer na época atual
    pub fn record_proposer(&mut self, proposer_id: &str) {
        if self.current_stats.proposers.insert(proposer_id.to_string()) {
            self.current_stats.unique_proposers = self.current_stats.proposers.len() as u64;
        }
    }

    /// Atualiza a taxa de participação dos validadores
    pub fn update_validator_participation(&mut self, participation_rate: f32) {
        self.current_stats.validator_participation = participation_rate;
    }

    /// Configura o número de blocos esperados para a época
    pub fn set_expected_blocks(&mut self, expected_blocks: u64) {
        self.current_stats.blocks_expected = expected_blocks;
        // Atualiza a taxa de blocos perdidos
        if expected_blocks > 0 {
            let missed = expected_blocks.saturating_sub(self.current_stats.blocks_produced);
            self.current_stats.block_miss_rate = missed as f32 / expected_blocks as f32;
        }
    }
}

/// Representa uma transição entre épocas
#[derive(Debug, Clone)]
pub struct EpochTransition {
    /// Número da época anterior
    pub previous_epoch: u64,

    /// Número da nova época
    pub new_epoch: u64,

    /// Bloco em que ocorreu a transição
    pub transition_block: u64,

    /// Bloco em que as mudanças devem ser ativadas
    pub activation_block: u64,

    /// Informações sobre a época anterior
    pub previous_epoch_info: EpochInfo,
}

impl EpochTransition {
    /// Verifica se é hora de ativar as mudanças desta transição
    pub fn should_activate(&self, current_block: u64) -> bool {
        current_block >= self.activation_block
    }
}
