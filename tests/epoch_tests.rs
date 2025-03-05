use kybelith::consensus::epoch::{EpochManager, EpochConfig, EpochTransition};


// Test helper para criar uma configuração de época com valores específicos
fn create_test_epoch_config(
    epoch_length: u64,
    min_epoch_time_secs: u64,
    max_epoch_time_secs: u64,
    activation_delay: u64
) -> EpochConfig {
    let mut config = EpochConfig::new(epoch_length);
    config.min_epoch_time_secs = min_epoch_time_secs;
    config.max_epoch_time_secs = max_epoch_time_secs;
    config.activation_delay = activation_delay;
    config
}

#[test]
fn test_epoch_initialization() {
    let config = create_test_epoch_config(100, 3600, 86400, 10);
    let manager = EpochManager::new(config);
    
    let current_info = manager.current_epoch_info();
    assert_eq!(current_info.epoch_number, 0, "Época inicial deve ser 0");
    assert_eq!(current_info.start_block, 0, "Bloco inicial deve ser 0");
    assert_eq!(current_info.end_block, 99, "Bloco final deve ser 99");
    assert!(!current_info.is_completed, "Época não deve estar completa");
}

#[test]
fn test_epoch_transition_by_blocks() {
    // Configura épocas curtas para teste
    let config = create_test_epoch_config(10, 0, 3600, 2); // min_epoch_time_secs = 0 para transição imediata
    let mut manager = EpochManager::new(config);
    
    // Processa blocos sem causar transição
    for i in 0..9 {
        let transition = manager.process_new_block(i);
        assert!(transition.is_none(), "Não deve haver transição antes do final da época");
    }
    
    // Processa o bloco que causa transição
    let transition = manager.process_new_block(10);
    assert!(transition.is_some(), "Deve haver transição após atingir o tamanho da época");
    
    let transition_info = transition.unwrap();
    assert_eq!(transition_info.previous_epoch, 0, "Época anterior deve ser 0");
    assert_eq!(transition_info.new_epoch, 1, "Nova época deve ser 1");
    assert_eq!(transition_info.transition_block, 10, "Bloco de transição deve ser 10");
    assert_eq!(transition_info.activation_block, 12, "Bloco de ativação deve ser 12 (10 + delay 2)");
    
    // Verifica se a época atual foi atualizada
    let current_info = manager.current_epoch_info();
    assert_eq!(current_info.epoch_number, 1, "Número da época atual deve ser 1");
    assert_eq!(current_info.start_block, 10, "Bloco inicial da nova época deve ser 10");
}

#[test]
fn test_epoch_statistics_update() {
    let config = create_test_epoch_config(100, 3600, 86400, 10);
    let mut manager = EpochManager::new(config);
    
    // Registra algumas transações e estatísticas
    manager.record_transaction();
    manager.record_transaction();
    manager.record_proposer("validator1");
    manager.update_validator_participation(0.85);
    manager.set_expected_blocks(120);
    
    // Verifica se as estatísticas foram atualizadas
    let epoch_info = manager.current_epoch_info();
    assert_eq!(epoch_info.stats.transactions_processed, 2, "Deve registrar 2 transações");
    assert_eq!(epoch_info.stats.unique_proposers, 1, "Deve registrar 1 proposer único");
    assert_eq!(epoch_info.stats.validator_participation, 0.85, "Deve registrar participação de 85%");
    assert_eq!(epoch_info.stats.blocks_expected, 120, "Deve registrar 120 blocos esperados");
}

#[test]
fn test_epoch_history() {
    let config = create_test_epoch_config(10, 0, 3600, 2); // min_epoch_time_secs = 0 para transição imediata
    let mut manager = EpochManager::new(config);
    
    // Gera três épocas
    for i in 0..30 {
        let _ = manager.process_new_block(i);
    }
    
    // Verifica o histórico de épocas
    let history = manager.epoch_history();
    assert_eq!(history.len(), 2, "Deve haver 2 épocas no histórico");
    
    assert_eq!(history[0].epoch_number, 0, "Primeira época no histórico deve ser 0");
    assert_eq!(history[0].start_block, 0, "Bloco inicial da primeira época deve ser 0");
    assert_eq!(history[0].end_block, 9, "Bloco final da primeira época deve ser 9");
    assert!(history[0].is_completed, "Primeira época deve estar completa");
    
    assert_eq!(history[1].epoch_number, 1, "Segunda época no histórico deve ser 1");
    assert_eq!(history[1].start_block, 10, "Bloco inicial da segunda época deve ser 10");
    assert_eq!(history[1].end_block, 19, "Bloco final da segunda época deve ser 19");
    assert!(history[1].is_completed, "Segunda época deve estar completa");
}

#[test]
fn test_epoch_transition_activation() {
    let config = create_test_epoch_config(10, 0, 3600, 5); // min_epoch_time_secs = 0 para transição imediata
    let mut manager = EpochManager::new(config);
    
    // Gera uma transição
    for i in 0..11 {
        let _ = manager.process_new_block(i);
    }
    
    // Obtém o histórico
    let history = manager.epoch_history();
    assert_eq!(history.len(), 1, "Deve haver 1 época no histórico");
    
    // Cria uma transição baseada na época concluída
    let transition = EpochTransition {
        previous_epoch: 0,
        new_epoch: 1,
        transition_block: 10,
        activation_block: 15, // 5 blocos depois da transição
        previous_epoch_info: history[0].clone(),
    };
    
    // Verifica ativação
    assert!(!transition.should_activate(14), "Não deve ativar antes do bloco 15");
    assert!(transition.should_activate(15), "Deve ativar exatamente no bloco 15");
    assert!(transition.should_activate(16), "Deve ativar após o bloco 15");
}