use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{self, Duration};

use crate::config::Settings;
use crate::consensus::block_proposal::{
    BlockProposal, ProposalVerifier, ProposalVote, VotingCoordinator,
};
use crate::consensus::epoch::{EpochConfig, EpochManager, EpochTransition};
use crate::consensus::evaluate_threat_level;
use crate::consensus::reputation::{ReputationAction, ReputationSystem};
use crate::consensus::threat_detection::ThreatLevel;
use crate::consensus::types::{
    ConsensusError, ConsensusState, ConsensusType, NetworkCondition, NetworkMetrics,
    VerificationResult,
};
use crate::consensus::validator::{Validator, ValidatorSet};

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
        let validator_config = crate::consensus::validator::ValidatorSetConfig {
            min_validators: config.consensus.min_validators as usize,
            min_stake: (config.consensus.min_stake_percentage * 100.0) as u64,
            proposer_cooldown: 10,
        };

        let validators = Arc::new(RwLock::new(ValidatorSet::with_config(
            initial_validators,
            validator_config,
        )));

        // Configura o sistema de reputação
        let reputation = Arc::new(RwLock::new(ReputationSystem::new()));

        // Configura o gerenciador de épocas
        let epoch_config = EpochConfig::new(config.consensus.epoch_length);
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

    pub fn add_validator(&mut self, validator: Validator) -> Result<(), Box<dyn std::error::Error>> {
        let mut validators = self.validators.write().unwrap(); // Obtenha uma referência mutável
        validators.add_validator(validator); // Use o método add_validator do ValidatorSet
        Ok(())
    }

    /// Inicia o sistema de consenso (em background)
    pub async fn start(&mut self) -> Result<(), ConsensusError> {
        {
            let mut is_running = self.is_running.write().unwrap();
            if *is_running {
                warn!("Tentativa de iniciar consenso quando já está em execução");
                return Err(ConsensusError::InternalError(
                    "O consenso já está em execução".to_string(),
                ));
            }
            *is_running = true;
        }

        let consensus_type = self.state.read().unwrap().consensus_type;
        info!(
            "🚀 Iniciando consenso QuantumFlex com modo: {:?}",
            consensus_type
        );
        info!(
            "📊 Validadores iniciais: {} (mínimo necessário: {})",
            self.validators.read().unwrap().len(),
            self.validators.read().unwrap().config().min_validators
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
        let tx_adapt = tx.clone();
        let adaptation_interval = self.config.consensus.adaptation_interval_blocks
            * self.config.consensus.block_interval_sec;

        tokio::spawn(async move {
            let interval = Duration::from_secs(adaptation_interval);
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
                warn!("🛑 Falha ao enviar mensagem de shutdown");
            }
        }

        {
            let mut is_running = self.is_running.write().unwrap();
            *is_running = false;
        }

        info!("🏁 Sistema de consenso QuantumFlex interrompido");
        Ok(())
    }

    /// Processa uma proposta de bloco
    pub async fn process_block_proposal(
        &self,
        proposal: BlockProposal,
    ) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            debug!(
                "📥 Encaminhando proposta de bloco {} para processamento",
                proposal.block_hash
            );
            tx.send(ConsensusMessage::NewBlockProposal(proposal))
                .await
                .map_err(|_| {
                    ConsensusError::InternalError(
                        "Falha ao enviar proposta para processamento".to_string(),
                    )
                })?;
            Ok(())
        } else {
            warn!("❌ Tentativa de processar proposta com consenso inativo");
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Processa um voto em uma proposta
    pub async fn process_vote(&self, vote: ProposalVote) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            debug!(
                "📥 Encaminhando voto de {} para bloco {}",
                vote.validator_id, vote.block_hash
            );
            tx.send(ConsensusMessage::NewVote(vote))
                .await
                .map_err(|_| {
                    ConsensusError::InternalError(
                        "Falha ao enviar voto para processamento".to_string(),
                    )
                })?;
            Ok(())
        } else {
            warn!("❌ Tentativa de processar voto com consenso inativo");
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Solicita a criação de uma proposta de bloco (para validadores)
    pub async fn request_block_proposal(&self) -> Result<(), ConsensusError> {
        if let Some(tx) = &self.message_sender {
            debug!("🔔 Solicitando criação de nova proposta de bloco");
            tx.send(ConsensusMessage::ProposeBlock).await.map_err(|_| {
                ConsensusError::InternalError("Falha ao solicitar proposta de bloco".to_string())
            })?;
            Ok(())
        } else {
            warn!("❌ Tentativa de solicitar proposta com consenso inativo");
            Err(ConsensusError::InternalError(
                "Consenso não está em execução".to_string(),
            ))
        }
    }

    /// Atualiza as métricas de rede
    pub fn update_network_metrics(&self, metrics: NetworkMetrics) {
        debug!(
            "📊 Atualizando métricas de rede: latência={:.1}ms, perda_msgs={:.2}%",
            metrics.average_latency_ms,
            metrics.message_loss_rate * 100.0
        );
        let mut current = self.network_metrics.write().unwrap();
        *current = metrics;
    }

    /// Avalia as condições da rede e adapta o tipo de consenso se necessário
    pub fn evaluate_and_adapt(&self) -> ConsensusType {
        let metrics = self.network_metrics.read().unwrap();
        let mut state = self.state.write().unwrap();

        let threat_level = evaluate_threat_level(&metrics);
        let network_condition = metrics.network_condition();

        debug!("📊 Métricas de rede: perda_msgs={:.2}%, latência={:.1}ms, peers={}, validadores={}/{} ativos/suspeitos, forks={}",
               metrics.message_loss_rate * 100.0,
               metrics.average_latency_ms,
               metrics.connected_peers,
               metrics.active_validators,
               metrics.suspicious_validators,
               metrics.fork_count);

        let new_consensus_type = match (threat_level, network_condition) {
            (ThreatLevel::High, _) => {
                info!("⚠️ Ameaça alta detectada! Adaptando para PBFT para priorizar segurança.");
                ConsensusType::PBFT
            }
            (_, NetworkCondition::Unstable) => {
                info!(
                    "🌩️ Rede instável detectada. Adaptando para PBFT para priorizar consistência."
                );
                ConsensusType::PBFT
            }
            (ThreatLevel::Low, NetworkCondition::Stable) => {
                info!("✅ Condições de rede ótimas. Adaptando para PoS para priorizar eficiência.");
                ConsensusType::PoS
            }
            _ => {
                info!("⚖️ Condições de rede mistas. Usando modo Híbrido para equilíbrio.");
                ConsensusType::Hybrid
            }
        };

        if state.consensus_type != new_consensus_type {
            info!(
                "🔄 Adaptando consenso de {:?} para {:?}",
                state.consensus_type, new_consensus_type
            );
            info!(
                "📈 Detalhes da adaptação: nível de ameaça={:?}, condição de rede={:?}",
                threat_level, network_condition
            );

            let previous_type = state.consensus_type;
            state.adapt_to(new_consensus_type);
            info!(
                "🔄 Adapted consensus from {:?} to {:?}",
                previous_type, new_consensus_type
            );

            debug!(
                "⏱️ Tempo desde última adaptação: {:.2}s",
                state.last_adaptation.elapsed().as_secs_f32()
            );
        } else {
            debug!(
                "✓ Mantendo consenso atual {:?} (ameaça={:?}, rede={:?})",
                state.consensus_type, threat_level, network_condition
            );
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
    ) {
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

        info!(
            "🧠 Worker de consenso iniciado com tipo: {:?}",
            current_consensus_type
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
                            "📬 Recebida proposta de bloco: {} da altura {}",
                            proposal.block_hash, proposal.block_height
                        );

                        // Verifica a proposta
                        let verifier =
                            ProposalVerifier::new(Arc::clone(&validators), Arc::clone(&reputation));

                        match verifier.verify(&proposal) {
                            Ok(VerificationResult::Valid) => {
                                info!("✅ Proposta de bloco válida: altura={}, hash={}, proposer={}, txs={}", 
                                     proposal.block_height,
                                     proposal.block_hash,
                                     proposal.proposer_id,
                                     proposal.transaction_hashes.len());

                                // Detalhes técnicos em log de debug
                                debug!("🔍 Detalhes da proposta: parent_hash={}, timestamp={}, idade={:?}", 
                                      proposal.parent_hash,
                                      proposal.timestamp,
                                      proposal.age());

                                // Aqui seriam adicionadas ações específicas para cada tipo de consenso
                                match current_consensus_type {
                                    ConsensusType::PoS => {
                                        // Em PoS, a proposta é aceita diretamente se o proposer for válido
                                        // e tiver stake suficiente
                                        let validators_guard = validators.read().unwrap();
                                        if let Some(proposer) =
                                            validators_guard.get_validator(&proposal.proposer_id)
                                        {
                                            if validators_guard.has_minimum_stake_fraction(
                                                &proposal.proposer_id,
                                                0.01,
                                            ) {
                                                // Simulação de aceitação imediata no PoS
                                                info!("⚡ PoS: Bloco {} aceito por stake suficiente ({} tokens)", 
                                                     proposal.block_hash, proposer.stake);
                                            } else {
                                                debug!("🔒 PoS: Proposer tem stake insuficiente: {} tokens", proposer.stake);
                                            }
                                        }
                                    }
                                    ConsensusType::PBFT => {
                                        // Em PBFT, inicia-se a fase de preparação (votação)
                                        info!(
                                            "🔄 PBFT: Iniciando fase de votação para bloco {}",
                                            proposal.block_hash
                                        );
                                        // Log detalhado para depuração de problemas no PBFT
                                        debug!("📋 PBFT: Solicitando votos de {} validadores para bloco {}",
                                              validators.read().unwrap().count_active(),
                                              proposal.block_hash);
                                        // Aqui seriam enviados pedidos de voto para todos os validadores
                                    }
                                    ConsensusType::Hybrid | ConsensusType::Adaptive => {
                                        // No modo híbrido/adaptativo, combina características dos dois
                                        info!("⚖️ Híbrido/Adaptativo: Processando bloco {} com verificação de duas fases", 
                                             proposal.block_hash);

                                        // Log detalhado da estratégia híbrida
                                        debug!("🔀 Estratégia híbrida: Verificação de stake + votação parcial para bloco {}",
                                              proposal.block_hash);
                                        // Poderia usar stake para pré-seleção e depois votação para confirmação
                                    }
                                }

                                // Atualiza a altura do bloco se for maior que a atual
                                if proposal.block_height > current_block_height {
                                    current_block_height = proposal.block_height;
                                    debug!(
                                        "📏 Altura do bloco atualizada para {}",
                                        current_block_height
                                    );

                                    let transition = {
                                        let mut epoch_mgr = epoch_manager.write().unwrap();
                                        epoch_mgr.process_new_block(current_block_height)
                                    };

                                    if let Some(transition) = transition {
                                        info!(
                                            "🔄 Transição de época detectada: {} -> {}",
                                            transition.previous_epoch, transition.new_epoch
                                        );
                                        Self::process_epoch_transition(&transition).await;
                                    }
                                }
                            }
                            Ok(VerificationResult::Invalid(reason)) => {
                                warn!(
                                    "❌ Proposta de bloco rejeitada: hash={}, altura={}, razão={}",
                                    proposal.block_hash, proposal.block_height, reason
                                );

                                // Penaliza o proposer por proposta inválida
                                let mut rep = reputation.write().unwrap();
                                if let Err(e) = rep.update_reputation(
                                    &proposal.proposer_id,
                                    ReputationAction::InvalidBlockProposed,
                                ) {
                                    debug!("⚠️ Falha ao atualizar reputação: {}", e);
                                } else {
                                    debug!(
                                        "📉 Reputação de {} reduzida por proposta inválida",
                                        proposal.proposer_id
                                    );
                                }
                            }
                            Ok(VerificationResult::Indeterminate) => {
                                debug!("⏳ Proposta de bloco indeterminada: hash={}, altura={}, aguardando mais informações", 
                                      proposal.block_hash, proposal.block_height);
                            }
                            Err(e) => {
                                error!("🛑 Erro ao verificar proposta de bloco: hash={}, altura={}, erro={}", 
                                     proposal.block_hash, proposal.block_height, e);
                            }
                        }
                    }
                    ConsensusMessage::NewVote(vote) => {
    debug!(
        "🗳️ Recebido voto para bloco {}: {} vota {}",
        vote.block_hash,
        vote.validator_id,
        if vote.is_in_favor { "a favor ✓" } else { "contra ✗" }
    );

    // Processa o voto 
    let vote_result = voting_coordinator.process_vote(vote.clone());
    
    match vote_result {
        Ok(_) => {
            // Verifica se atingiu finalidade
            if voting_coordinator.has_reached_finality(&vote.block_hash) {
                info!(
                    "🏁 Bloco {} atingiu finalidade! Consenso alcançado.",
                    vote.block_hash
                );

                // Notifica sobre o bloco finalizado
                // Em implementação real, isso seria enviado pelo canal

                // Limpa os votos para este bloco
                voting_coordinator.clear_votes(&vote.block_hash);
            } else if let Some(tally) = voting_coordinator.tally_votes(&vote.block_hash) {
                // Log de progresso da votação
                debug!(
                    "📊 Progresso da votação para bloco {}: {}/{} votos, {:.1}% a favor", 
                    vote.block_hash, 
                    tally.votes_in_favor, 
                    tally.total_votes,
                    tally.approval_percentage
                );
            }
        },
        Err(e) => {
            warn!("⚠️ Erro ao processar voto: {}", e);
        }
    }
}, 

ConsensusMessage::ProposeBlock => {
        debug!("🔔 Solicitação para propor um bloco recebida ");

        // Seleciona um proposer com base no tipo de consenso atual
        let validator_set = validators.read().unwrap();
        let reputation_sys = reputation.read().unwrap();

        let proposer_result = match current_consensus_type {
            ConsensusType::PoS => {
                info!(
                    "🏆 Selecionando proposer pelo PoS para altura {}",
                    current_block_height + 1
                );
                validator_set
                    .select_proposer_stake_weighted(current_block_height + 1)
            }
            ConsensusType::PBFT => {
                info!("🔄 Selecionando proposer pelo PBFT (round-robin) para altura {}", current_block_height + 1);
                validator_set.select_proposer_round_robin(current_block_height + 1)
            }
            ConsensusType::Hybrid | ConsensusType::Adaptive => {
                info!(
                    "⚖️ Selecionando proposer pelo modo híbrido para altura {}",
                    current_block_height + 1
                );
                validator_set.select_proposer_weighted(
                    current_block_height + 1,
                    &reputation_sys,
                )
            }
        };

        match proposer_result {
            Ok(proposer) => {
                info!(
                    "✨ Proposer selecionado para bloco {}: {} (stake: {})",
                    current_block_height + 1,
                    proposer.id,
                    proposer.stake
                );
                // Em implementação real, se este nó fosse o proposer,
                // criaria e propagaria um bloco
            }
            Err(e) => {
                warn!("❌ Falha ao selecionar proposer: {}", e);
            }
        }
    },


// E então, se você realmente precisa do processamento de timeout, ele deveria estar em seu próprio bloco de case
ConsensusMessage::ConsensusTimeout => {
    warn!("⏰ Timeout de consenso detectado");

    // Lida com o timeout (depende do tipo de consenso)
    match current_consensus_type {
        ConsensusType::PBFT => {
            // Em PBFT, inicia uma nova view
            info!("🔁 Timeout em PBFT: Iniciando nova view");
        }
        _ => {
            // Outros tipos têm tratamentos diferentes para timeout
            info!(
                "⚠️ Timeout em consenso {:?}: Tentando novamente",
                current_consensus_type
            );
        }
    } 
} 

                  
                    ConsensusMessage::EvaluateAndAdapt => {
                        debug!(
                            "🔍 Avaliando condições de rede para possível adaptação de consenso"
                        );

                        // Em uma implementação real, coletaria métricas de rede
                        // e usaria o método evaluate_and_adapt para decidir sobre adaptação

                        // Por simplicidade, alternamos entre os tipos de consenso
                        current_consensus_type = match current_consensus_type {
                            ConsensusType::PoS => {
                                info!("🔄 Adaptando consenso: PoS → Híbrido");
                                ConsensusType::Hybrid
                            }
                            ConsensusType::PBFT => {
                                info!("🔄 Adaptando consenso: PBFT → PoS");
                                ConsensusType::PoS
                            }
                            ConsensusType::Hybrid => {
                                info!("🔄 Adaptando consenso: Híbrido → PBFT");
                                ConsensusType::PBFT
                            }
                            ConsensusType::Adaptive => {
                                // No modo adaptativo, a decisão seria baseada em métricas
                                // Por simplicidade, mantemos o mesmo tipo
                                debug!("🧠 Mantendo consenso adaptativo");
                                ConsensusType::Adaptive
                            }
                        };
                    }
                    ConsensusMessage::NewEpoch(transition) => {
                        info!(
                            "🔄 Nova época iniciada: {}. Ativação no bloco {}",
                            transition.new_epoch, transition.activation_block
                        );

                        // Implementa lógica de transição de época
                        // Por exemplo, poderia recalcular distribuição de stake, ajustar parâmetros, etc.
                        Self::process_epoch_transition(&transition).await;
                    }
                    ConsensusMessage::BlockFinalized {
                        block_hash,
                        block_height,
                    } => {
                        info!(
                            "✅ Bloco {} da altura {} finalizado",
                            block_hash, block_height
                        );

                        // Atualiza estado interno com o novo bloco finalizado
                        current_block_height = block_height;

                        // Atualiza reputação dos validadores com base nos votos corretos/incorretos
                        // Em implementação real, isto seria mais complexo
                        debug!(
                            "📊 Atualizando estado para bloco finalizado {}",
                            block_height
                        );
                    }
                    ConsensusMessage::Shutdown => {
                        info!("🛑 Recebido comando para interromper consenso");
                        break;
                    }
                }
            }
        }

        info!("👋 Worker de consenso finalizado");
    }

    /// Processa uma transição de época
async fn process_epoch_transition(transition: &EpochTransition) {
    // Em uma implementação real, esta função realizaria várias ações:
    // 1. Recalcular distribuição de stake
    // 2. Ajustar parâmetros do consenso
    // 3. Remover validadores inativos
    // 4. Adicionar novos validadores que atingiram o stake mínimo

    info!(
        "📆 Processando transição de época {} → {}",
        transition.previous_epoch, transition.new_epoch
    );

    // Simula algum processamento
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Log detalhado
    debug!(
        "📊 Estatísticas da época {}: {} blocos produzidos, {:.1}% participação de validadores",
        transition.previous_epoch,
        transition.previous_epoch_info.stats.blocks_produced,
        transition.previous_epoch_info.stats.validator_participation * 100.0
    );

    info!(
        "✅ Transição de época processada. Ativação no bloco {}",
        transition.activation_block
    );
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

    /// Seleciona o próximo proposer com base no tipo de consenso atual
    pub fn select_proposer(&self, block_height: u64) -> Result<Validator, ConsensusError> {
        let state = self.state.read().unwrap();
        let validators = self.validators.read().unwrap();
        let reputation = self.reputation.read().unwrap();

        debug!(
            "🔍 Selecionando proposer para altura {} usando modo {:?}",
            block_height, state.consensus_type
        );

        match state.consensus_type {
            ConsensusType::PoS => {
                // Seleção baseada em stake com VRF
                debug!("💰 Usando seleção ponderada por stake");
                validators.select_proposer_stake_weighted(block_height)
            }
            ConsensusType::PBFT => {
                // Seleção rotativa entre validadores
                debug!("🔄 Usando seleção round-robin");
                validators.select_proposer_round_robin(block_height)
            }
            ConsensusType::Hybrid | ConsensusType::Adaptive => {
                // Seleção ponderada por stake e reputação
                debug!("⚖️ Usando seleção ponderada por stake e reputação");
                validators.select_proposer_weighted(block_height, &reputation)
            }
        }
    }


    /// Atualiza o stake de um validador
    pub fn update_validator_stake(
        &self,
        validator_id: &str,
        new_stake: u64,
    ) -> Result<(), ConsensusError> {
        let mut validators_guard = self.validators.write().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do conjunto de validadores".to_string(),
            )
        })?;

        // Atualiza o stake
        validators_guard.update_stake(validator_id, new_stake)?;

        info!(
            "💰 Stake do validador {} atualizado para {}",
            validator_id, new_stake
        );

        Ok(())
    }

    /// Obtém informações sobre um validador específico
    pub fn get_validator_info(&self, validator_id: &str) -> Result<ValidatorInfo, ConsensusError> {
        let validators_guard = self.validators.read().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do conjunto de validadores".to_string(),
            )
        })?;

        let reputation_guard = self.reputation.read().map_err(|_| {
            ConsensusError::InternalError("Falha ao obter lock do sistema de reputação".to_string())
        })?;

        // Obtém o validador
        let validator = validators_guard
            .get_validator(validator_id)
            .ok_or_else(|| {
                ConsensusError::InvalidProposer(format!(
                    "Validador não encontrado: {}",
                    validator_id
                ))
            })?;

        // Obtém a reputação
        let reputation = reputation_guard
            .get_reputation(validator_id)
            .map(|rep| rep.score)
            .unwrap_or(50.0);

        // Obtém informações de épocas
        let epoch_manager = self.epoch_manager.read().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do gerenciador de épocas".to_string(),
            )
        })?;

        // Constrói o objeto de informações
        Ok(ValidatorInfo {
            id: validator.id.clone(),
            address: validator.address.clone(),
            stake: validator.stake,
            is_active: validator.is_active,
            reputation,
            is_banned: reputation_guard.is_banned(validator_id),
            last_proposed_block: validator.last_proposed_block,
            is_eligible_current_block: validator.is_eligible_to_propose(
                self.state.read().unwrap().current_block_height,
                validators_guard.config().proposer_cooldown,
            ),
            current_epoch: epoch_manager.current_epoch_number(),
        })
    }

    /// Força uma transição de época (útil para testes)
    pub fn force_epoch_transition(&self) -> Result<EpochTransition, ConsensusError> {
        let mut epoch_manager = self.epoch_manager.write().map_err(|_| {
            ConsensusError::InternalError(
                "Falha ao obter lock do gerenciador de épocas".to_string(),
            )
        })?;

        let current_block = self.state.read().unwrap().current_block_height;
        let transition = epoch_manager
            .process_new_block(current_block + 1000)
            .ok_or_else(|| {
                ConsensusError::InternalError("Falha ao forçar transição de época".to_string())
            })?;

        info!(
            "🔄 Transição de época forçada: {} → {}",
            transition.previous_epoch, transition.new_epoch
        );

        Ok(transition)
    }
}

/// Métricas do sistema de consenso para monitoramento
#[derive(Debug, Clone)]
pub struct ConsensusMetrics {
    /// Tipo de consenso atual
    pub consensus_type: ConsensusType,
    /// Altura do bloco atual
    pub current_block_height: u64,
    /// Número de validadores ativos
    pub active_validators: usize,
    /// Número total de validadores
    pub total_validators: usize,
    /// Reputação média dos validadores
    pub average_reputation: f32,
    /// Número de validadores suspeitos
    pub suspicious_validators: usize,
    /// Condição atual da rede
    pub network_condition: NetworkCondition,
    /// Latência média da rede (ms)
    pub average_latency_ms: f32,
    /// Taxa de perdas de mensagens (0.0-1.0)
    pub message_loss_rate: f32,
    /// Se o consenso está em execução
    pub is_running: bool,
    /// Época atual
    pub current_epoch: u64,
}

/// Informações detalhadas sobre um validador
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    /// ID do validador
    pub id: String,
    /// Endereço do validador
    pub address: String,
    /// Stake atual do validador
    pub stake: u64,
    /// Se o validador está ativo
    pub is_active: bool,
    /// Pontuação de reputação atual
    pub reputation: f32,
    /// Se o validador está banido
    pub is_banned: bool,
    /// Último bloco proposto pelo validador
    pub last_proposed_block: Option<u64>,
    /// Se o validador é elegível para propor no bloco atual
    pub is_eligible_current_block: bool,
    /// Época atual
    pub current_epoch: u64,

}

