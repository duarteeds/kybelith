pub mod block_proposal;
pub mod epoch;
pub mod quantum_flex;
pub mod reputation;
pub mod threat_detection;
pub mod types;
pub mod validator;



// Reexporta os itens principais para uso externo
pub use block_proposal::{BlockProposal, ProposalVerifier, ProposalVote, VotingCoordinator, VotingResult, send_block_proposal};
pub use epoch::{EpochConfig, EpochManager, EpochTransition};
pub use quantum_flex::QuantumFlexConsensus as OtherQuantumFlexConsensus;
pub use quantum_flex::{ConsensusMetrics, ValidatorInfo}; // Reexporta de quantum_flex, onde estão definidos
pub use reputation::{ReputationAction, ReputationSystem};
pub use threat_detection::{
    detect_threats, evaluate_threat_level, ThreatInfo, ThreatLevel, ThreatType,
};
pub use types::{
    ConsensusDecision, ConsensusError, ConsensusState, ConsensusStatus, ConsensusType,
    NetworkCondition, NetworkMetrics, VerificationResult,
};
pub use validator::{Validator, ValidatorSet};


use crate::config::Settings;
use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{self, Duration};

/// Mensagens internas do sistema de consenso
#[derive(Debug, Clone)]
pub enum ConsensusMessage {
    /// Nova proposta de bloco recebida
    NewBlockProposal(BlockProposal),

    /// Novo voto recebido
    NewVote(ProposalVote),

    /// Solicitação para propor um bloco
    ProposeBlock,

    /// Notificação de timeout de consenso
    ConsensusTimeout,

    /// Solicitação para avaliar e adaptar o consenso
    EvaluateAndAdapt,

    /// Notificação de nova época
    NewEpoch(EpochTransition),

    /// Notificação de novo bloco finalizado
    BlockFinalized {
        block_hash: String,
        block_height: u64,
    },

    /// Comando para interromper o consenso
    Shutdown,
}

/// Estrutura principal do consenso QuantumFlex
pub struct QuantumFlexConsensus {
    /// Configurações do sistema
    config: Arc<Settings>,

    /// Estado atual do consenso
    state: RwLock<ConsensusState>,

    /// Conjunto de validadores
    validators: Arc<RwLock<ValidatorSet>>,

    /// Sistema de reputação
    reputation: Arc<RwLock<ReputationSystem>>,

    /// Gerenciador de épocas
    epoch_manager: Arc<RwLock<EpochManager>>,

    /// Métricas de rede
    network_metrics: RwLock<NetworkMetrics>,

    /// Canal para enviar mensagens para o worker de consenso
    message_sender: Option<Sender<ConsensusMessage>>,

    /// Flag indicando se o consenso está em execução
    is_running: RwLock<bool>,
}

impl QuantumFlexConsensus {
    /// Cria uma nova instância do consenso QuantumFlex
    pub fn new(config: Arc<Settings>, initial_validators: Vec<Validator>) -> Self {
        // Configura o conjunto de validadores
        let validator_config = validator::ValidatorSetConfig {
            min_validators: config.consensus.min_validators as usize,
            min_stake: (config.consensus.min_stake_percentage * 100.0) as u64,
            proposer_cooldown: 10, // Número de blocos antes que um validador possa propor novamente
        };

        let validators = Arc::new(RwLock::new(ValidatorSet::with_config(
            initial_validators,
            validator_config,
        )));

        // Configura o sistema de reputação
        let reputation = Arc::new(RwLock::new(ReputationSystem::new()));

        // Configura o gerenciador de épocas
        let epoch_config = epoch::EpochConfig::new(config.consensus.epoch_length);
        let epoch_manager = Arc::new(RwLock::new(EpochManager::new(epoch_config)));

        // Obtém o tipo de consenso inicial da configuração
        let initial_consensus_type =
            match ConsensusType::from_str(&config.consensus.initial_consensus_type) {
                Ok(t) => t,
                Err(_) => {
                    warn!(
                        "Tipo de consenso inválido na configuração: {}. Usando Adaptive.",
                        config.consensus.initial_consensus_type
                    );
                    ConsensusType::Adaptive
                }
            };

        Self {
            config,
            state: RwLock::new(ConsensusState::new(initial_consensus_type)),
            validators,
            reputation,
            epoch_manager,
            network_metrics: RwLock::new(NetworkMetrics::default()),
            message_sender: None,
            is_running: RwLock::new(false),
        }
    }

    /// Inicia o sistema de consenso (em background)
    // Apenas o trecho relevante com o problema de delimitadores

    /// Inicia o sistema de consenso (em background)
    pub async fn start(&mut self) -> Result<(), ConsensusError> {
        {
            let mut is_running = self.is_running.write().unwrap();
            if *is_running {
                return Err(ConsensusError::InternalError(
                    "O consenso já está em execução".to_string(),
                ));
            }
            *is_running = true;
        }

        info!(
            "Iniciando consenso QuantumFlex com modo: {:?}",
            self.state.read().unwrap().consensus_type
        );

        // Cria canais para comunicação com o worker
        let (tx, rx) = mpsc::channel(100);
        self.message_sender = Some(tx.clone());

        // Clona referências para o worker
        let config = Arc::clone(&self.config);
        let validators = Arc::clone(&self.validators);
        let reputation = Arc::clone(&self.reputation);
        let epoch_manager = Arc::clone(&self.epoch_manager);
        let is_running = Arc::new(RwLock::new(*self.is_running.read().unwrap()));

        // Inicia o worker em uma tarefa separada
        tokio::spawn(async move {
            Self::consensus_worker(
                config,
                validators,
                reputation,
                epoch_manager,
                rx,
                is_running,
            )
            .await;
        });

        // Agenda avaliações periódicas do consenso
        let adaptation_config = Arc::clone(&self.config);
        let tx_adapt = tx.clone();

        tokio::spawn(async move {
            let interval = Duration::from_secs(
                adaptation_config.consensus.adaptation_interval_blocks
                    * adaptation_config.consensus.block_interval_sec,
            );

            let mut interval_timer = time::interval(interval);
            loop {
                interval_timer.tick().await;
                if tx_adapt
                    .send(ConsensusMessage::EvaluateAndAdapt)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(())
    }

    /// Interrompe o sistema de consenso
    pub async fn stop(&self) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            if tx.send(ConsensusMessage::Shutdown).await.is_err() {
                warn!("Falha ao enviar mensagem de shutdown");
            }
        }

        {
            let mut is_running = self.is_running.write().unwrap();
            *is_running = false;
        }

        info!("Sistema de consenso QuantumFlex interrompido");
        Ok(())
    }

    /// Processa uma proposta de bloco
    pub async fn process_block_proposal(
        &self,
        proposal: BlockProposal,
    ) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            tx.send(ConsensusMessage::NewBlockProposal(proposal))
                .await
                .map_err(|_| {
                    ConsensusError::InternalError(
                        "Falha ao enviar proposta para processamento".to_string(),
                    )
                })?;
            Ok(())
        } else {
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Processa um voto em uma proposta
    pub async fn process_vote(&self, vote: ProposalVote) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            tx.send(ConsensusMessage::NewVote(vote))
                .await
                .map_err(|_| {
                    ConsensusError::InternalError(
                        "Falha ao enviar voto para processamento".to_string(),
                    )
                })?;
            Ok(())
        } else {
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Solicita a criação de uma proposta de bloco (para validadores)
    pub async fn request_block_proposal(&self) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            tx.send(ConsensusMessage::ProposeBlock).await.map_err(|_| {
                ConsensusError::InternalError("Falha ao solicitar proposta de bloco".to_string())
            })?;
            Ok(())
        } else {
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Atualiza as métricas de rede
    pub fn update_network_metrics(&self, metrics: NetworkMetrics) {
        let mut current = self.network_metrics.write().unwrap();
        *current = metrics;
    }

    /// Avalia as condições da rede e adapta o tipo de consenso se necessário
    pub fn evaluate_and_adapt(&self) -> ConsensusType {
        let metrics = self.network_metrics.read().unwrap();
        let mut state = self.state.write().unwrap();

        // Avalia ameaças e condições de rede
        let threat_level = threat_detection::evaluate_threat_level(&metrics);
        let network_condition = metrics.network_condition();

        // Determina o melhor tipo de consenso com base nas condições atuais
        let new_consensus_type = match (threat_level, network_condition) {
            (threat_detection::ThreatLevel::High, _) => {
                debug!("Ameaça alta detectada! Adaptando para PBFT.");
                ConsensusType::PBFT // Prioriza segurança em caso de ameaça alta
            }
            (_, NetworkCondition::Unstable) => {
                debug!("Rede instável detectada. Adaptando para PBFT.");
                ConsensusType::PBFT // Prioriza consistência em rede instável
            }
            (threat_detection::ThreatLevel::Low, NetworkCondition::Stable) => {
                debug!("Condições ótimas. Adaptando para PoS.");
                ConsensusType::PoS // Prioriza eficiência em condições ótimas
            }
            _ => {
                debug!("Condições mistas. Usando modo Híbrido.");
                ConsensusType::Hybrid // Balanceado para condições mistas
            }
        };

        // Atualiza o tipo de consenso se necessário
        if state.consensus_type != new_consensus_type {
            info!(
                "Adaptando consenso de {:?} para {:?} devido a ameaça={:?}, rede={:?}",
                state.consensus_type, new_consensus_type, threat_level, network_condition
            );
            state.consensus_type = new_consensus_type;
        }

        new_consensus_type
    }

    /// Worker principal do consenso (executa em background)
    async fn consensus_worker(
        config: Arc<Settings>,
        validators: Arc<RwLock<ValidatorSet>>,
        reputation: Arc<RwLock<ReputationSystem>>,
        epoch_manager: Arc<RwLock<EpochManager>>,
        mut rx: Receiver<ConsensusMessage>,
        is_running: Arc<RwLock<bool>>,
    ) -> () {
        // Estado local do worker
        let mut current_block_height = 0u64;
        let mut current_consensus_type =
            ConsensusType::from_str(&config.consensus.initial_consensus_type)
                .unwrap_or(ConsensusType::Adaptive);

        // Coordenador de votação
        let mut voting_coordinator = VotingCoordinator::new(
            Arc::clone(&validators),
            Arc::clone(&reputation),
            config.consensus.finality_threshold_percentage,
        );

        // Loop principal do worker
        while {
            let is_running = is_running.read().unwrap();
            *is_running
        } {
            // Aguarda a próxima mensagem
            if let Some(message) = rx.recv().await {
                match message {
                    ConsensusMessage::NewBlockProposal(proposal) => {
                        debug!(
                            "Recebida proposta de bloco: {} da altura {}",
                            proposal.block_hash, proposal.block_height
                        );

                        // Verifica a proposta
                        let verifier =
                            ProposalVerifier::new(Arc::clone(&validators), Arc::clone(&reputation));

                        match verifier.verify(&proposal) {
                            Ok(VerificationResult::Valid) => {
                                info!(
                                    "Proposta de bloco {} válida de {}",
                                    proposal.block_hash, proposal.proposer_id
                                );

                                // Aqui seriam adicionadas ações específicas para cada tipo de consenso
                                match current_consensus_type {
                                    ConsensusType::PoS => {
                                        // Em PoS, a proposta é aceita diretamente se o proposer for válido
                                        // e tiver stake suficiente
                                    }
                                    ConsensusType::PBFT => {
                                        // Em PBFT, inicia-se a fase de preparação (votação)
                                    }
                                    ConsensusType::Hybrid | ConsensusType::Adaptive => {
                                        // No modo híbrido/adaptativo, combina características dos dois
                                    }
                                }

                                // Atualiza a altura do bloco se for maior que a atual
                                if proposal.block_height > current_block_height {
                                    current_block_height = proposal.block_height;

                                    // Verifica se é hora de uma nova época
                                    let mut epoch_mgr = epoch_manager.write().unwrap();
                                    if let Some(transition) =
                                        epoch_mgr.process_new_block(current_block_height)
                                    {
                                        // Notifica sobre a transição de época
                                        info!(
                                            "Transição de época detectada: {} -> {}",
                                            transition.previous_epoch, transition.new_epoch
                                        );

                                        // Envia uma mensagem de nova época
                                        // (em uma implementação real, isso seria feito através do canal)
                                    }
                                }
                            }
                            Ok(VerificationResult::Invalid(reason)) => {
                                warn!(
                                    "Proposta de bloco {} rejeitada: {}",
                                    proposal.block_hash, reason
                                );

                                // Penaliza o proposer por proposta inválida
                                let mut rep = reputation.write().unwrap();
                                if let Err(e) = rep.update_reputation(
                                    &proposal.proposer_id,
                                    ReputationAction::InvalidBlockProposed,
                                ) {
                                    debug!("Falha ao atualizar reputação: {}", e);
                                }
                            }
                            Ok(VerificationResult::Indeterminate) => {
                                debug!("Proposta de bloco {} indeterminada, aguardando mais informações", 
                                      proposal.block_hash);
                            }
                            Err(e) => {
                                error!("Erro ao verificar proposta de bloco: {}", e);
                            }
                        }
                    }
                    ConsensusMessage::NewVote(vote) => {
                        debug!(
                            "Recebido voto para bloco {}: {} vota {}",
                            vote.block_hash,
                            vote.validator_id,
                            if vote.is_in_favor {
                                "a favor"
                            } else {
                                "contra"
                            }
                        );

                        // Processa o voto
                        match voting_coordinator.process_vote(vote.clone()) {
                            Ok(_) => {
                                // Verifica se atingiu finalidade
                                if voting_coordinator.has_reached_finality(&vote.block_hash) {
                                    info!("Bloco {} atingiu finalidade!", vote.block_hash);

                                    // Notifica sobre o bloco finalizado
                                    // (em uma implementação real, isso seria feito através do canal)

                                    // Limpa os votos para este bloco
                                    voting_coordinator.clear_votes(&vote.block_hash);
                                }
                            }
                            Err(e) => {
                                warn!("Erro ao processar voto: {}", e);
                            }
                        }
                    }
                    ConsensusMessage::ProposeBlock => {
                        debug!("Solicitação para propor um bloco recebida");

                        // Seleciona um proposer com base no tipo de consenso atual
                        // (em uma implementação real, verificaria se este nó é o proposer)
                    }
                    ConsensusMessage::ConsensusTimeout => {
                        warn!("Timeout de consenso detectado");

                        // Lida com o timeout (depende do tipo de consenso)
                        // Por exemplo, poderia iniciar uma nova rodada de consenso
                    }
                    ConsensusMessage::EvaluateAndAdapt => {
                        debug!("Avaliando condições de rede para possível adaptação de consenso");

                        // Em uma implementação real, coletaria métricas de rede
                        // e usaria o método evaluate_and_adapt para decidir sobre adaptação

                        // Por simplicidade, alternamos entre os tipos de consenso
                        current_consensus_type = match current_consensus_type {
                            ConsensusType::PoS => ConsensusType::Hybrid,
                            ConsensusType::PBFT => ConsensusType::PoS,
                            ConsensusType::Hybrid => ConsensusType::PBFT,
                            ConsensusType::Adaptive => {
                                // No modo adaptativo, a decisão seria baseada em métricas
                                // Por simplicidade, mantemos o mesmo tipo
                                ConsensusType::Adaptive
                            }
                        };

                        info!("Consenso adaptado para: {:?}", current_consensus_type);
                    }
                    ConsensusMessage::NewEpoch(transition) => {
                        info!(
                            "Nova época iniciada: {}. Ativação no bloco {}",
                            transition.new_epoch, transition.activation_block
                        );

                        // Implementa lógica de transição de época
                        // Por exemplo, poderia recalcular distribuição de stake, ajustar parâmetros, etc.
                    }
                    ConsensusMessage::BlockFinalized {
                        block_hash,
                        block_height,
                    } => {
                        info!("Bloco {} da altura {} finalizado", block_hash, block_height);

                        // Atualiza estado interno com o novo bloco finalizado
                        current_block_height = block_height;

                        // Atualiza reputação dos validadores com base nos votos corretos/incorretos
                        // (em uma implementação real, isto seria mais complexo)
                    }
                    ConsensusMessage::Shutdown => {
                        info!("Recebido comando para interromper consenso");
                        break;
                    }
                }
            }
        }

        info!("Worker de consenso finalizado");
    }

    /// Obtém o tipo de consenso atual
    pub fn get_consensus_type(&self) -> ConsensusType {
        self.state.read().unwrap().consensus_type
    }

    /// Obtém o estado atual de consenso
    pub fn get_state(&self) -> ConsensusState {
        self.state.read().unwrap().clone()
    }

    /// Verifica se o consenso está em execução
    pub fn is_running(&self) -> bool {
        *self.is_running.read().unwrap()
    }

    /// Obtém as métricas de rede atuais
    pub fn get_network_metrics(&self) -> NetworkMetrics {
        self.network_metrics.read().unwrap().clone()
    }
}
