use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Ações que podem afetar a reputação de um validador
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationAction {
    ValidBlockProposed,
    InvalidBlockProposed,
    CorrectVote,
    IncorrectVote,
    Timeout,
    DoubleVote,
    Offline,
    BackOnline,
    InvalidMessage,
    UnauthorizedProposal,
}

/// Reputação de um único validador
#[derive(Debug, Clone)]
pub struct ValidatorReputation {
    pub validator_id: String,
    pub score: f32,
    pub successful_proposals: u64,
    pub invalid_proposals: u64,
    pub correct_votes: u64,
    pub incorrect_votes: u64,
    pub timeouts: u64,
    pub double_votes: u64,
    pub last_seen: Instant,
    pub is_banned: bool,
    pub banned_until: Option<Instant>,
}

impl ValidatorReputation {
    pub fn new(validator_id: String) -> Self {
        Self {
            validator_id,
            score: 50.0,
            successful_proposals: 0,
            invalid_proposals: 0,
            correct_votes: 0,
            incorrect_votes: 0,
            timeouts: 0,
            double_votes: 0,
            last_seen: Instant::now(),
            is_banned: false,
            banned_until: None,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_offline(&self, threshold: Duration) -> bool {
        self.last_seen.elapsed() > threshold
    }

    pub fn ban(&mut self, duration: Duration) {
        self.is_banned = true;
        self.banned_until = Some(Instant::now() + duration);
        self.score = self.score.max(10.0);
    }

    pub fn check_ban_status(&mut self) -> bool {
        if let Some(until) = self.banned_until {
            if Instant::now() >= until {
                self.is_banned = false;
                self.banned_until = None;
                return true;
            }
        }
        false
    }

    pub fn to_serializable(&self) -> SerializableReputation {
        SerializableReputation {
            validator_id: self.validator_id.clone(),
            score: self.score,
            successful_proposals: self.successful_proposals,
            invalid_proposals: self.invalid_proposals,
            correct_votes: self.correct_votes,
            incorrect_votes: self.incorrect_votes,
            timeouts: self.timeouts,
            double_votes: self.double_votes,
            last_seen: self.last_seen.elapsed().as_secs(),
            is_banned: self.is_banned,
            banned_until: self.banned_until.map(|t| t.duration_since(Instant::now()).as_secs()),
        }
    }

    pub fn from_serializable(data: SerializableReputation, reference_time: Instant) -> Self {
        Self {
            validator_id: data.validator_id,
            score: data.score,
            successful_proposals: data.successful_proposals,
            invalid_proposals: data.invalid_proposals,
            correct_votes: data.correct_votes,
            incorrect_votes: data.incorrect_votes,
            timeouts: data.timeouts,
            double_votes: data.double_votes,
            last_seen: reference_time - Duration::from_secs(data.last_seen),
            is_banned: data.is_banned,
            banned_until: data.banned_until.map(|d| reference_time + Duration::from_secs(d)),
        }
    }
}

// Struct auxiliar para serialização, agora pública
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableReputation {
    validator_id: String,
    score: f32,
    successful_proposals: u64,
    invalid_proposals: u64,
    correct_votes: u64,
    incorrect_votes: u64,
    timeouts: u64,
    double_votes: u64,
    last_seen: u64, // Segundos desde a última vez visto
    is_banned: bool,
    banned_until: Option<u64>, // Segundos restantes do ban
}

/// Sistema de reputação que gerencia a reputação de todos os validadores
#[derive(Debug, Clone)]
pub struct ReputationSystem {
    reputations: HashMap<String, ValidatorReputation>,
    config: ReputationConfig,
}

/// Configurações para o sistema de reputação
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    pub valid_block_points: f32,
    pub invalid_block_penalty: f32,
    pub correct_vote_points: f32,
    pub incorrect_vote_penalty: f32,
    pub timeout_penalty: f32,
    pub double_vote_penalty: f32,
    pub offline_penalty: f32,
    pub back_online_points: f32,
    pub suspicious_threshold: f32,
    pub ban_threshold: f32,
    pub initial_ban_duration: Duration,
    pub decay_factor: f32,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            valid_block_points: 2.0,
            invalid_block_penalty: 10.0,
            correct_vote_points: 1.0,
            incorrect_vote_penalty: 5.0,
            timeout_penalty: 3.0,
            double_vote_penalty: 20.0,
            offline_penalty: 5.0,
            back_online_points: 1.0,
            suspicious_threshold: 30.0,
            ban_threshold: 15.0,
            initial_ban_duration: Duration::from_secs(3600),
            decay_factor: 0.9,
        }
    }
}

impl ReputationSystem {
    pub fn new() -> Self {
        Self {
            reputations: HashMap::new(),
            config: ReputationConfig::default(),
        }
    }

    pub fn config(&self) -> &ReputationConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ReputationConfig) {
        self.config = config;
    }

    pub fn ban_validator(&mut self, validator_id: &str, duration: Duration) -> Result<(), String> {
        let reputation = self.reputations.get_mut(validator_id).ok_or_else(|| format!("Validador não encontrado: {}", validator_id))?;
        reputation.ban(duration);
        Ok(())
    }

    pub fn get_reputation_mut(&mut self, validator_id: &str) -> Option<&mut ValidatorReputation> {
        self.reputations.get_mut(validator_id)
    }

    pub fn with_config(config: ReputationConfig) -> Self {
        Self {
            reputations: HashMap::new(),
            config,
        }
    }

    pub fn add_validator(&mut self, validator_id: String) {
        if !self.reputations.contains_key(&validator_id) {
            let reputation = ValidatorReputation::new(validator_id.clone());
            self.reputations.insert(validator_id.clone(), reputation);
            debug!("Adicionado novo validador ao sistema de reputação: {}", validator_id);
        }
    }

    pub fn update_reputation(&mut self, validator_id: &str, action: ReputationAction) -> Result<f32, String> {
        let reputation = self.reputations.get_mut(validator_id).ok_or_else(|| format!("Validador não encontrado: {}", validator_id))?;
        reputation.update_last_seen();
        if reputation.is_banned {
            reputation.check_ban_status();
            if reputation.is_banned {
                return Err(format!("Validador está banido: {}", validator_id));
            }
        }
        let adjustment = match action {
            ReputationAction::ValidBlockProposed => { reputation.successful_proposals += 1; self.config.valid_block_points }
            ReputationAction::InvalidBlockProposed => { reputation.invalid_proposals += 1; -self.config.invalid_block_penalty }
            ReputationAction::CorrectVote => { reputation.correct_votes += 1; self.config.correct_vote_points }
            ReputationAction::IncorrectVote => { reputation.incorrect_votes += 1; -self.config.incorrect_vote_penalty }
            ReputationAction::Timeout => { reputation.timeouts += 1; -self.config.timeout_penalty }
            ReputationAction::DoubleVote => { reputation.double_votes += 1; -self.config.double_vote_penalty }
            ReputationAction::Offline => -self.config.offline_penalty,
            ReputationAction::BackOnline => self.config.back_online_points,
            ReputationAction::InvalidMessage => -self.config.incorrect_vote_penalty,
            ReputationAction::UnauthorizedProposal => -self.config.invalid_block_penalty,
        };
        reputation.score = (reputation.score + adjustment).max(0.0).min(100.0);
        if adjustment < 0.0 && reputation.score < self.config.ban_threshold {
            let multiplier = (1.0 + reputation.double_votes as f32) * (1.0 + reputation.invalid_proposals as f32);
            let mult_factor = multiplier as u32;
            let ban_duration = self.config.initial_ban_duration * mult_factor;
            reputation.ban(ban_duration);
            info!("Validador {} banido por {:?} devido a pontuação baixa ({:.2})", validator_id, ban_duration, reputation.score);
        }
        if adjustment > 0.0 {
            debug!("Reputação de {} aumentou em {:.2} para {:.2} ({:?})", validator_id, adjustment, reputation.score, action);
        } else {
            info!("Reputação de {} diminuiu em {:.2} para {:.2} ({:?})", validator_id, -adjustment, reputation.score, action);
        }
        Ok(reputation.score)
    }

    pub fn set_reputation(&mut self, validator_id: &str, score: f32) -> Result<(), String> {
        let reputation = self.reputations.get_mut(validator_id).ok_or_else(|| format!("Validador não encontrado: {}", validator_id))?;
        reputation.score = score.max(0.0).min(100.0);
        Ok(())
    }

    pub fn get_reputation(&self, validator_id: &str) -> Option<&ValidatorReputation> {
        self.reputations.get(validator_id)
    }

    pub fn get_suspicious_validators(&self) -> Vec<&ValidatorReputation> {
        self.reputations.values().filter(|rep| rep.score < self.config.suspicious_threshold).collect()
    }

    pub fn count_suspicious_validators(&self) -> usize {
        self.get_suspicious_validators().len()
    }

    pub fn get_active_validators(&self) -> Vec<&ValidatorReputation> {
        self.reputations.values().filter(|rep| !rep.is_banned).collect()
    }

    pub fn is_banned(&self, validator_id: &str) -> bool {
        self.reputations.get(validator_id).map(|rep| rep.is_banned).unwrap_or(false)
    }

    pub fn update_offline_status(&mut self, offline_threshold: Duration) {
        let ids_to_update: Vec<String> = self.reputations.keys().filter(|id| {
            if let Some(rep) = self.reputations.get(*id) {
                rep.is_offline(offline_threshold) && !rep.is_banned
            } else {
                false
            }
        }).cloned().collect();
        for id in ids_to_update {
            let _ = self.update_reputation(&id, ReputationAction::Offline);
        }
    }

    pub fn average_reputation(&self) -> f32 {
        if self.reputations.is_empty() {
            return 50.0;
        }
        let sum: f32 = self.reputations.values().map(|rep| rep.score).sum();
        sum / self.reputations.len() as f32
    }
}