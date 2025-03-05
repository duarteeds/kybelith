use crate::consensus::reputation::ReputationSystem;
use crate::consensus::ConsensusError;
use log::{debug, info, warn};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Representa um validador na rede
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// ID único do validador (normalmente um hash de chave pública)
    pub id: String,

    /// Endereço na rede (IP:porta)
    pub address: String,

    /// Chave pública Dilithium do validador (para verificação de assinaturas)
    pub public_key: Vec<u8>,

    /// Quantidade de tokens em stake
    pub stake: u64,

    /// Se o validador está ativo no consenso atual
    pub is_active: bool,

    /// Quando o validador entrou no conjunto
    pub joined_at: u64, // Altura do bloco

    /// Última vez que o validador propôs um bloco (altura do bloco)
    pub last_proposed_block: Option<u64>,
}

impl Validator {
    /// Cria um novo validador
    pub fn new(id: String, address: String, public_key: Vec<u8>, stake: u64) -> Self {
        Self {
            id,
            address,
            public_key,
            stake,
            is_active: true,
            joined_at: 0,
            last_proposed_block: None,
        }
    }

    /// Verifica se o validador é elegível para propor em um determinado bloco
    pub fn is_eligible_to_propose(&self, current_block: u64, cooldown_blocks: u64) -> bool {
        if !self.is_active {
            return false;
        }

        // Se nunca propôs antes, é elegível
        if self.last_proposed_block.is_none() {
            return true;
        }

        // Verifica se já passou o período de cooldown desde a última proposta
        current_block >= self.last_proposed_block.unwrap() + cooldown_blocks
    }
}

/// Gerencia o conjunto de validadores participando do consenso
#[derive(Debug)]
pub struct ValidatorSet {
    /// Mapa de IDs para validadores
    validators: HashMap<String, Validator>,

    /// Validadores ordenados por stake (para seleção ponderada)
    validators_by_stake: Vec<String>,

    /// Configuração do conjunto de validadores
    config: ValidatorSetConfig,
}

/// Configuração para o conjunto de validadores
#[derive(Debug, Clone)]
pub struct ValidatorSetConfig {
    /// Número mínimo de validadores para o consenso funcionar
    pub min_validators: usize,

    /// Stake mínimo para se tornar validador
    pub min_stake: u64,

    /// Número de blocos antes que um validador possa propor novamente
    pub proposer_cooldown: u64,
}

impl Default for ValidatorSetConfig {
    fn default() -> Self {
        Self {
            min_validators: 4,
            min_stake: 1000,
            proposer_cooldown: 10,
        }
    }
}

impl ValidatorSet {
    /// Cria um novo conjunto de validadores vazio
    pub fn new(validators: Vec<Validator>) -> Self {
        let mut set = Self {
            validators: HashMap::new(),
            validators_by_stake: Vec::new(),
            config: ValidatorSetConfig::default(),
        };

        // Adiciona os validadores iniciais
        for validator in validators {
            set.add_validator(validator);
        }

        set
    }

    /// Cria um conjunto de validadores com configuração personalizada
    pub fn with_config(validators: Vec<Validator>, config: ValidatorSetConfig) -> Self {
        let mut set = Self {
            validators: HashMap::new(),
            validators_by_stake: Vec::new(),
            config,
        };

        // Adiciona os validadores iniciais
        for validator in validators {
            set.add_validator(validator);
        }

        set
    }

    /// Adiciona um validador ao conjunto
    pub fn add_validator(&mut self, validator: Validator) -> bool {
    if validator.stake < self.config.min_stake {
        warn!(
            "Validador {} rejeitado: stake insuficiente ({} < {})",
            validator.id, validator.stake, self.config.min_stake
        );
        return false;
    }
    if !self.validators.contains_key(&validator.id) {
        let validator_id = validator.id.clone();
        self.validators.insert(validator_id.clone(), validator);
        self.rebuild_stake_ordering();
        info!("Validador {} adicionado ao conjunto", validator_id);
        return true; // Sucesso na adição
    }
    false // Falha por duplicata
}

    /// Remove um validador do conjunto
    pub fn remove_validator(&mut self, validator_id: &str) -> bool {
        if self.validators.remove(validator_id).is_some() {
            self.rebuild_stake_ordering();
            info!("Validador {} removido do conjunto", validator_id);
            return true;
        }

        false
    }

    /// Atualiza o stake de um validador
    pub fn update_stake(
        &mut self,
        validator_id: &str,
        new_stake: u64,
    ) -> Result<(), ConsensusError> {
        let validator = self.validators.get_mut(validator_id).ok_or_else(|| {
            ConsensusError::InvalidProposer(format!("Validador não encontrado: {}", validator_id))
        })?;

        // Verifica se o novo stake é suficiente
        if new_stake < self.config.min_stake {
            return Err(ConsensusError::ValidationFailed(format!(
                "Stake insuficiente: {} < {}",
                new_stake, self.config.min_stake
            )));
        }

        validator.stake = new_stake;
        self.rebuild_stake_ordering();

        debug!(
            "Stake do validador {} atualizado para {}",
            validator_id, new_stake
        );

        Ok(())
    }

    /// Atualiza o status de atividade de um validador
    pub fn set_validator_active(
        &mut self,
        validator_id: &str,
        active: bool,
    ) -> Result<(), ConsensusError> {
        let validator = self.validators.get_mut(validator_id).ok_or_else(|| {
            ConsensusError::InvalidProposer(format!("Validador não encontrado: {}", validator_id))
        })?;

        validator.is_active = active;

        if active {
            debug!("Validador {} marcado como ativo", validator_id);
        } else {
            info!("Validador {} marcado como inativo", validator_id);
        }

        Ok(())
    }

    /// Atualiza o campo last_proposed_block de um validador
    pub fn update_last_proposed(
        &mut self,
        validator_id: &str,
        block_height: u64,
    ) -> Result<(), ConsensusError> {
        let validator = self.validators.get_mut(validator_id).ok_or_else(|| {
            ConsensusError::InvalidProposer(format!("Validador não encontrado: {}", validator_id))
        })?;

        validator.last_proposed_block = Some(block_height);
        debug!("Validador {} propôs o bloco {}", validator_id, block_height);

        Ok(())
    }

    /// Verifica se um validador existe no conjunto
    pub fn contains(&self, validator_id: &str) -> bool {
        self.validators.contains_key(validator_id)
    }

    pub fn config(&self) -> &ValidatorSetConfig {
        &self.config
    }

    /// Obtém um validador pelo ID
    pub fn get_validator(&self, validator_id: &str) -> Option<&Validator> {
        self.validators.get(validator_id)
    }

    /// Obtém o número total de validadores no conjunto
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Verifica se o conjunto está vazio
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Obtém todos os validadores ativos
    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators.values().filter(|v| v.is_active).collect()
    }

    /// Conta o número de validadores ativos
    pub fn count_active(&self) -> usize {
        self.active_validators().len()
    }

    /// Verifica se há validadores suficientes para o consenso
    pub fn has_quorum(&self) -> bool {
        self.count_active() >= self.config.min_validators
    }

    /// Reconstrói a ordenação de validadores por stake
    fn rebuild_stake_ordering(&mut self) {
        // Cria uma lista temporária de IDs de validadores
        let mut ids: Vec<String> = self.validators.keys().cloned().collect();

        // Ordena por stake (do maior para o menor)
        ids.sort_by(|a, b| {
            let stake_a = self.validators.get(a).map(|v| v.stake).unwrap_or(0);
            let stake_b = self.validators.get(b).map(|v| v.stake).unwrap_or(0);
            stake_b.cmp(&stake_a) // Ordem decrescente
        });

        self.validators_by_stake = ids;
    }

    /// Seleciona um proposer com base no stake (ponderado por stake)
    pub fn select_proposer_stake_weighted(
        &self,
        block_height: u64,
    ) -> Result<Validator, ConsensusError> {
        // Verifica se há validadores suficientes
        if !self.has_quorum() {
            return Err(ConsensusError::InternalError(format!(
                "Quórum insuficiente: {} < {}",
                self.count_active(),
                self.config.min_validators
            )));
        }

        // Filtra validadores elegíveis
        let eligible: Vec<&Validator> = self
            .validators
            .values()
            .filter(|v| {
                v.is_active && v.is_eligible_to_propose(block_height, self.config.proposer_cooldown)
            })
            .collect();

        if eligible.is_empty() {
            return Err(ConsensusError::InternalError(
                "Nenhum validador elegível disponível".to_string(),
            ));
        }

        // Calcula o stake total para ponderação
        let total_stake: u64 = eligible.iter().map(|v| v.stake).sum();

        // Escolhe um validador com probabilidade proporcional ao stake
        // Usa o bloco como seed para determinismo
        let mut rng = StdRng::seed_from_u64(block_height);
        let threshold = rng.gen_range(0..total_stake);

        let mut cumulative = 0;
        for validator in &eligible {
            cumulative += validator.stake;
            if cumulative > threshold {
                return Ok((*validator).clone());
            }
        }

        // Fallback para o caso improvável de não ter escolhido ninguém
        Ok(eligible[0].clone())
    }

    /// Seleciona um proposer usando um sistema round-robin
    pub fn select_proposer_round_robin(
        &self,
        block_height: u64,
    ) -> Result<Validator, ConsensusError> {
        // Verifica se há validadores suficientes
        if !self.has_quorum() {
            return Err(ConsensusError::InternalError(format!(
                "Quórum insuficiente: {} < {}",
                self.count_active(),
                self.config.min_validators
            )));
        }

        // Filtra validadores ativos
        let active: Vec<&Validator> = self.validators.values().filter(|v| v.is_active).collect();

        if active.is_empty() {
            return Err(ConsensusError::InternalError(
                "Nenhum validador ativo disponível".to_string(),
            ));
        }

        // Escolhe o validador com base no bloco (round-robin)
        let index = (block_height as usize) % active.len();
        Ok(active[index].clone())
    }

    /// Seleciona um proposer usando ponderação combinada (stake e reputação)
    pub fn select_proposer_weighted(
        &self,
        block_height: u64,
        reputation: &ReputationSystem,
    ) -> Result<Validator, ConsensusError> {
        // Verifica se há validadores suficientes
        if !self.has_quorum() {
            return Err(ConsensusError::InternalError(format!(
                "Quórum insuficiente: {} < {}",
                self.count_active(),
                self.config.min_validators
            )));
        }

        // Filtra validadores elegíveis
        let eligible: Vec<&Validator> = self
            .validators
            .values()
            .filter(|v| {
                v.is_active && v.is_eligible_to_propose(block_height, self.config.proposer_cooldown)
            })
            .collect();

        if eligible.is_empty() {
            return Err(ConsensusError::InternalError(
                "Nenhum validador elegível disponível".to_string(),
            ));
        }

        // Calcula pontuações combinadas (stake * reputação)
        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut total_score = 0.0;

        for validator in &eligible {
            // Obtém reputação (ou usa valor neutro se não estiver no sistema)
            let rep_score = reputation
                .get_reputation(&validator.id)
                .map(|rep| rep.score)
                .unwrap_or(50.0);

            // Calcula pontuação combinada: stake * (reputação/50)
            // Isso faz com que reputação 50 seja neutra, acima aumenta, abaixo diminui
            let score = (validator.stake as f64) * (rep_score as f64 / 50.0);
            scores.insert(validator.id.clone(), score);
            total_score += score;
        }

        // Escolhe um validador com probabilidade proporcional à pontuação combinada
        let mut rng = StdRng::seed_from_u64(block_height);
        let threshold = rng.gen_range(0.0..total_score);

        let mut cumulative = 0.0;
        for validator in &eligible {
            let score = scores.get(&validator.id).unwrap_or(&0.0);
            cumulative += score;
            if cumulative >= threshold {
                return Ok((*validator).clone());
            }
        }

        // Fallback para o caso improvável de não ter escolhido ninguém
        Ok(eligible[0].clone())
    }

    /// Obtém a lista de validadores ordenados por stake
    pub fn validators_by_stake(&self) -> &Vec<String> {
        &self.validators_by_stake
    }

    /// Calcula o stake total de todos os validadores ativos
    pub fn total_active_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.is_active)
            .map(|v| v.stake)
            .sum()
    }

    /// Verifica se um validador tem pelo menos uma fração mínima do stake total
    pub fn has_minimum_stake_fraction(&self, validator_id: &str, min_fraction: f64) -> bool {
        let total_stake = self.total_active_stake();
        if total_stake == 0 {
            return false;
        }

        if let Some(validator) = self.validators.get(validator_id) {
            let stake_fraction = validator.stake as f64 / total_stake as f64;
            return stake_fraction >= min_fraction;
        }

        false
    }
}
