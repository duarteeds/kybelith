use crate::consensus::reputation::{ReputationAction, ReputationSystem};
use crate::consensus::types::{ConsensusError, VerificationResult};
use crate::consensus::validator::ValidatorSet;
use log::{debug, warn};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::p2p::NetworkManager;
use crate::p2p::message::Message;
use crate::p2p::types::MessageType;
use serde::{Serialize, Deserialize};
use log::error;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    pub block_hash: String,
    pub block_height: u64,
    pub parent_hash: String,
    pub timestamp: u64,
    pub proposer_id: String,
    pub signature: Vec<u8>,
    pub transaction_hashes: Vec<String>,
    pub consensus_data: Vec<u8>,
    pub received_at: u64,
}

impl BlockProposal {
    pub fn new(
        block_hash: String,
        block_height: u64,
        parent_hash: String,
        proposer_id: String,
        transaction_hashes: Vec<String>,
        signature: Vec<u8>,
        consensus_data: Vec<u8>,
    ) -> Self {
        Self {
            block_hash,
            block_height,
            parent_hash,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            proposer_id,
            signature,
            transaction_hashes,
            consensus_data,
            received_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        }
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        now - self.received_at > timeout.as_millis() as u64
    }

    pub fn age(&self) -> Duration {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        Duration::from_millis(now - self.received_at)
    }

    pub fn transaction_count(&self) -> usize {
        self.transaction_hashes.len()
    }
}

/// Verifica propostas de blocos
pub struct ProposalVerifier {
    validators: Arc<RwLock<ValidatorSet>>,
    reputation: Arc<RwLock<ReputationSystem>>,
}

impl ProposalVerifier {
    pub fn new(
        validators: Arc<RwLock<ValidatorSet>>,
        reputation: Arc<RwLock<ReputationSystem>>,
    ) -> Self {
        Self {
            validators,
            reputation,
        }
    }

    pub fn verify(&self, proposal: &BlockProposal) -> Result<VerificationResult, ConsensusError> {
        let validators = self.validators.read().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do conjunto de validadores".to_string(),
            )
        })?;

        if let Some(v) = validators.get_validator(&proposal.proposer_id) {
            if !v.is_active {
                warn!(
                    "Proposta rejeitada: validador {} não está ativo",
                    proposal.proposer_id
                );
                return Ok(VerificationResult::Invalid(
                    "Validador não está ativo".to_string(),
                ));
            }
        } else {
            warn!(
                "Proposta rejeitada: validador {} desconhecido",
                proposal.proposer_id
            );
            return Ok(VerificationResult::Invalid(
                "Validador desconhecido".to_string(),
            ));
        }

        if proposal.signature.is_empty() {
            warn!(
                "Proposta rejeitada: assinatura vazia de {}",
                proposal.proposer_id
            );
            return Ok(VerificationResult::Invalid(
                "Assinatura inválida".to_string(),
            ));
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let time_diff = if current_time > proposal.timestamp {
            current_time - proposal.timestamp
        } else {
            proposal.timestamp - current_time
        };

        if time_diff > 300_000 {
            warn!(
                "Proposta rejeitada: timestamp divergente por {} ms",
                time_diff
            );
            return Ok(VerificationResult::Invalid(
                "Timestamp inválido".to_string(),
            ));
        }

        let mut reputation = self.reputation.write().map_err(|_| {
            ConsensusError::InternalError("Falha ao obter lock do sistema de reputação".to_string())
        })?;

        if let Err(e) = reputation
            .update_reputation(&proposal.proposer_id, ReputationAction::ValidBlockProposed)
        {
            debug!("Não foi possível atualizar reputação: {}", e);
        }

        debug!(
            "Proposta do bloco {} por {} verificada com sucesso",
            proposal.block_height, proposal.proposer_id
        );

        Ok(VerificationResult::Valid)
    }
}

/// Envia uma proposta de bloco para a rede
pub fn send_block_proposal(network: &mut NetworkManager, block: Vec<u8>) {
    let message = Message {
        sender: "local_node_id".to_string(),
        message_type: MessageType::BlockProposal,
        payload: block,
    };
    if let Err(e) = network.broadcast_message(message) {
    error!("Falha ao transmitir mensagem: {}", e);
}

}

/// Voto em uma proposta de bloco
#[derive(Debug, Clone)]
pub struct ProposalVote {
    pub block_hash: String,
    pub block_height: u64,
    pub validator_id: String,
    pub is_in_favor: bool,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl ProposalVote {
    pub fn new(
        block_hash: String,
        block_height: u64,
        validator_id: String,
        is_in_favor: bool,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            block_hash,
            block_height,
            validator_id,
            is_in_favor,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

/// Resultado da votação em uma proposta
#[derive(Debug, Clone)]
pub struct VotingResult {
    pub block_hash: String,
    pub block_height: u64,
    pub total_votes: usize,
    pub votes_in_favor: usize,
    pub votes_against: usize,
    pub approval_percentage: f32,
    pub reached_quorum: bool,
    pub is_approved: bool,
}

/// Coordena a votação em propostas de blocos
pub struct VotingCoordinator {
    validators: Arc<RwLock<ValidatorSet>>,
    reputation: Arc<RwLock<ReputationSystem>>,
    current_votes: std::collections::HashMap<String, Vec<ProposalVote>>,
    approval_threshold: f32,
}

impl VotingCoordinator {
    pub fn new(
        validators: Arc<RwLock<ValidatorSet>>,
        reputation: Arc<RwLock<ReputationSystem>>,
        approval_threshold: f32,
    ) -> Self {
        Self {
            validators,
            reputation,
            current_votes: std::collections::HashMap::new(),
            approval_threshold,
        }
    }

    pub fn process_vote(&mut self, vote: ProposalVote) -> Result<bool, ConsensusError> {
        let validators = self.validators.read().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do conjunto de validadores".to_string(),
            )
        })?;

        if !validators.contains(&vote.validator_id) {
            warn!(
                "Voto rejeitado: validador {} desconhecido",
                vote.validator_id
            );
            return Err(ConsensusError::InvalidProposer(format!(
                "Validador desconhecido: {}",
                vote.validator_id
            )));
        }

        let votes = self
            .current_votes
            .entry(vote.block_hash.clone())
            .or_insert_with(Vec::new);

        if votes.iter().any(|v| v.validator_id == vote.validator_id) {
            warn!(
                "Tentativa de double-voting detectada: {} para bloco {}",
                vote.validator_id, vote.block_hash
            );
            let mut reputation = self.reputation.write().map_err(|_| {
                ConsensusError::InternalError(
                    "Falha ao obter lock do sistema de reputação".to_string(),
                )
            })?;
            if let Err(e) = reputation.update_reputation(&vote.validator_id, ReputationAction::DoubleVote) {
                debug!("Não foi possível atualizar reputação: {}", e);
            }
            return Err(ConsensusError::ValidationFailed(
                "Tentativa de double-voting".to_string(),
            ));
        }

        votes.push(vote.clone());
        debug!(
            "Voto de {} para bloco {} registrado: {}",
            vote.validator_id,
            vote.block_hash,
            if vote.is_in_favor { "a favor" } else { "contra" }
        );
        Ok(true)
    }

    pub fn tally_votes(&self, block_hash: &str) -> Option<VotingResult> {
        let votes = self.current_votes.get(block_hash)?;
        if votes.is_empty() {
            return None;
        }

        let total_votes = votes.len();
        let votes_in_favor = votes.iter().filter(|v| v.is_in_favor).count();
        let votes_against = total_votes - votes_in_favor;
        let approval_percentage = (votes_in_favor as f32 / total_votes as f32) * 100.0;

        let validators = match self.validators.read() {
            Ok(v) => v,
            Err(_) => return None,
        };

        let total_validators = validators.count_active();
        let reached_quorum = total_votes >= (total_validators * 2 / 3);
        let is_approved = approval_percentage >= self.approval_threshold;

        let block_height = votes[0].block_height;

        Some(VotingResult {
            block_hash: block_hash.to_string(),
            block_height,
            total_votes,
            votes_in_favor,
            votes_against,
            approval_percentage,
            reached_quorum,
            is_approved: reached_quorum && is_approved,
        })
    }

    pub fn clear_votes(&mut self, block_hash: &str) {
        self.current_votes.remove(block_hash);
    }

    pub fn has_reached_finality(&self, block_hash: &str) -> bool {
        match self.tally_votes(block_hash) {
            Some(result) => result.is_approved,
            None => false,
        }
    }
}