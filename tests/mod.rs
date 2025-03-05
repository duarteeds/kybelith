// Integra todos os módulos de teste do consenso
mod reputation_tests;
mod validator_tests;
mod adaptation_tests;
mod epoch_tests;

// Testes de integração específicos que usam múltiplos componentes em conjunto
#[cfg(test)]
mod integration {
    use kybelith::config::Settings;
    use kybelith::consensus::{
        QuantumFlexConsensus, 
        Validator, 
        ConsensusType,
        BlockProposal,
        ProposalVote
    };
    use std::sync::Arc;
    
    // Cria uma instância de consenso para testes
    fn create_test_consensus() -> QuantumFlexConsensus {
        let mut config = Settings::default();
        config.consensus.initial_consensus_type = "ADAPTIVE".to_string();
        config.consensus.min_validators = 3;
        config.consensus.epoch_length = 10;
        
        let validators = vec![
            Validator::new(
                "validator1".to_string(), 
                "127.0.0.1:8001".to_string(), 
                vec![1, 2, 3, 4], 
                5000
            ),
            Validator::new(
                "validator2".to_string(), 
                "127.0.0.1:8002".to_string(), 
                vec![5, 6, 7, 8], 
                3000
            ),
            Validator::new(
                "validator3".to_string(), 
                "127.0.0.1:8003".to_string(), 
                vec![9, 10, 11, 12], 
                2000
            ),
        ];
        
        QuantumFlexConsensus::new(Arc::new(config), validators)
    }
    
    #[tokio::test]
    async fn test_consensus_startup_shutdown() {
        let mut consensus = create_test_consensus();
        
        // Inicia o consenso
        let result = consensus.start().await;
        assert!(result.is_ok(), "Inicialização do consenso deve ser bem-sucedida");
        assert!(consensus.is_running(), "Consenso deve estar em execução após start()");
        
        // Aguarda um momento para o worker iniciar
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Para o consenso
        let result = consensus.stop().await;
        assert!(result.is_ok(), "Parada do consenso deve ser bem-sucedida");
        
        // Aguarda um momento para o worker finalizar
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        assert!(!consensus.is_running(), "Consenso não deve estar em execução após stop()");
    }
    
    #[tokio::test]
    async fn test_process_block_proposal() {
        let mut consensus = create_test_consensus();
        
        // Inicia o consenso
        let _ = consensus.start().await;
        
        // Cria uma proposta de bloco
        let proposal = BlockProposal::new(
            "block123".to_string(),
            1,
            "block000".to_string(),
            "validator1".to_string(),
            vec!["tx1".to_string(), "tx2".to_string()],
            vec![1, 2, 3, 4], // Assinatura simulada
            vec![], // Dados extras
        );
        
        // Processa a proposta
        let result = consensus.process_block_proposal(proposal).await;
        assert!(result.is_ok(), "Processamento de proposta deve ser bem-sucedido");
        
        // Aguarda um momento para o processamento
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Para o consenso
        let _ = consensus.stop().await;
    }
    
    #[tokio::test]
    async fn test_process_vote() {
        let mut consensus = create_test_consensus();
        
        // Inicia o consenso
        let _ = consensus.start().await;
        
        // Cria um voto
        let vote = ProposalVote::new(
            "block123".to_string(),
            1,
            "validator2".to_string(),
            true, // A favor
            vec![5, 6, 7, 8], // Assinatura simulada
        );
        
        // Processa o voto
        let result = consensus.process_vote(vote).await;
        assert!(result.is_ok(), "Processamento de voto deve ser bem-sucedido");
        
        // Aguarda um momento para o processamento
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Para o consenso
        let _ = consensus.stop().await;
    }
    
    #[test]
    fn test_consensus_type_getters() {
        let consensus = create_test_consensus();
        
        // Obtém o tipo de consenso
        let consensus_type = consensus.get_consensus_type();
        assert_eq!(consensus_type, ConsensusType::Adaptive, 
                  "Tipo de consenso inicial deve ser Adaptive");
        
        // Obtém o estado do consenso
        let state = consensus.get_state();
        assert_eq!(state.consensus_type, ConsensusType::Adaptive,
                  "Tipo de consenso no estado deve ser Adaptive");
        assert_eq!(state.current_block_height, 0,
                  "Altura do bloco inicial deve ser 0");
    }
}