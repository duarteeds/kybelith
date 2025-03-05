use env_logger;
use kybelith::config::Settings;
use kybelith::consensus::quantum_flex::QuantumFlexConsensus;
use kybelith::consensus::{BlockProposal, ProposalVote, Validator};
use log::{info, LevelFilter};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    info!("Iniciando teste do sistema de consenso QuantumFlex");

    let mut settings = Settings::default();
    settings.consensus.initial_consensus_type = "ADAPTIVE".to_string();
    settings.consensus.min_validators = 3;
    settings.consensus.min_stake_percentage = 1.0;
    settings.consensus.epoch_length = 10;
    settings.consensus.block_interval_sec = 5;
    settings.consensus.adaptation_interval_blocks = 3;

    let validators = vec![
        Validator::new(
            "validator1".to_string(),
            "127.0.0.1:8001".to_string(),
            vec![1, 2, 3, 4],
            5000,
        ),
        Validator::new(
            "validator2".to_string(),
            "127.0.0.1:8002".to_string(),
            vec![5, 6, 7, 8],
            3000,
        ),
        Validator::new(
            "validator3".to_string(),
            "127.0.0.1:8003".to_string(),
            vec![9, 10, 11, 12],
            2000,
        ),
    ];

    let mut consensus = QuantumFlexConsensus::new(Arc::new(settings), validators.clone());
    info!("Validadores fornecidos: {:?}", validators);

    info!("Iniciando o sistema de consenso");
    consensus.start().await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("Simulando condições de rede iniciais");
    let simulated_loss_rate = 0.05;
    let simulated_latency_ms = 10.0;
    let simulated_peers = 3;
    info!(
        "Condições simuladas: perda={:.2}%, latência={:.1}ms, peers={}",
        simulated_loss_rate * 100.0,
        simulated_latency_ms,
        simulated_peers
    );

    info!("Estado inicial do consenso: {:?}", consensus.get_state());
    info!(
        "Tipo de consenso atual: {:?}",
        consensus.get_consensus_type()
    );
    info!("Consenso está rodando: {}", consensus.is_running());

    info!("Simulando aleatoriedade quântica para seleção de proposer");
    let mut rng = rand::thread_rng();
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let random_stake = rng.gen_range(0..total_stake);
    let mut cumulative_stake = 0;
    let proposer = validators
        .iter()
        .find(|v| {
            cumulative_stake += v.stake;
            cumulative_stake >= random_stake
        })
        .unwrap_or(&validators[0]);
    info!(
        "Proposer selecionado (PoS com aleatoriedade): {}",
        proposer.id
    );

    let proposal = BlockProposal::new(
        "block123".to_string(),
        1,
        "block000".to_string(),
        proposer.id.clone(),
        vec!["tx1".to_string(), "tx2".to_string()],
        vec![1, 2, 3, 4],
        vec![],
    );

    info!("Enviando proposta de bloco");
    consensus.process_block_proposal(proposal).await?;

    let vote1 = ProposalVote::new(
        "block123".to_string(),
        1,
        "validator2".to_string(),
        true,
        vec![5, 6, 7, 8],
    );
    let vote2 = ProposalVote::new(
        "block123".to_string(),
        1,
        "validator3".to_string(),
        true,
        vec![9, 10, 11, 12],
    );

    info!("Enviando votos");
    consensus.process_vote(vote1).await?;
    consensus.process_vote(vote2).await?;

    info!("Solicitando criação de bloco");
    consensus.request_block_proposal().await?;

    info!("Testando adaptação de consenso");
    let new_type = consensus.evaluate_and_adapt();
    info!("Tipo de consenso após adaptação: {:?}", new_type);

    info!("Aguardando alguns segundos para observar o comportamento...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    let metrics = consensus.get_network_metrics();
    info!("Métricas após simulação: {:?}", metrics);

    let new_validator = Validator::new(
        "validator4".to_string(),
        "127.0.0.1:8004".to_string(),
        vec![13, 14, 15, 16],
        5000,
    );
    info!("Adicionando novo validador");
    consensus.add_validator(new_validator)?;

    info!("Atualizando stake de um validador");
    consensus.update_validator_stake("validator1", 6000)?;

    let validator_info = consensus.get_validator_info("validator1")?;
    info!("Informações do validador: {:?}", validator_info);

    info!("Parando o sistema de consenso");
    consensus.stop().await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("Teste concluído com sucesso!");
    Ok(())
}
