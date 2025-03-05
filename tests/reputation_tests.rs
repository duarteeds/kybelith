use kybelith::consensus::reputation::{ReputationSystem, ReputationAction};
use std::time::Instant;
use kybelith::consensus::reputation::SerializableReputation;
use kybelith::consensus::reputation::ValidatorReputation;
use std::time::Duration;

#[test]
fn test_reputation_initial_score() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    
    let reputation = system.get_reputation("validator1").unwrap();
    assert_eq!(reputation.score, 50.0, "Reputação inicial deve ser 50.0");
}

#[test]
fn test_reputation_valid_block_increases_score() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    
    let result = system.update_reputation("validator1", ReputationAction::ValidBlockProposed);
    assert!(result.is_ok(), "Atualização da reputação deve ser bem-sucedida");
    
    let new_score = result.unwrap();
    let initial_score = 50.0;
    let config = system.config().clone(); // Clona o valor retornado por config()
    
    assert!(new_score > initial_score, "Score deve aumentar após propor bloco válido");
    assert_eq!(new_score, initial_score + config.valid_block_points, 
              "Aumento deve ser exatamente valid_block_points");
}

#[test]
fn test_reputation_invalid_block_decreases_score() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    
    let result = system.update_reputation("validator1", ReputationAction::InvalidBlockProposed);
    assert!(result.is_ok(), "Atualização da reputação deve ser bem-sucedida");
    
    let new_score = result.unwrap();
    let initial_score = 50.0;
    let config = system.config().clone(); // Clona o valor retornado por config()
    
    assert!(new_score < initial_score, "Score deve diminuir após propor bloco inválido");
    assert_eq!(new_score, initial_score - config.invalid_block_penalty,
              "Diminuição deve ser exatamente invalid_block_penalty");
}

#[test]
fn test_reputation_double_vote_causes_ban() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    
    // Reduz a reputação para próximo do limiar de ban
    let low_score = system.config().ban_threshold + 1.0;
    let _ = system.set_reputation("validator1", low_score); // Assume que adicionamos este método
    
    // Aplica penalidade por double vote
    let result = system.update_reputation("validator1", ReputationAction::DoubleVote);
    assert!(result.is_ok());
    
    // Verifica se o validador foi banido
    assert!(system.is_banned("validator1"), "Validador deve ser banido após double vote");
}

#[test]
fn test_reputation_ban_expires() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    
    let mut config = system.config().clone();
    config.initial_ban_duration = std::time::Duration::from_millis(500);
    system.set_config(config);
    
    let _ = system.ban_validator("validator1", std::time::Duration::from_millis(500));
    assert!(system.is_banned("validator1"), "Validador deve estar banido inicialmente");
    
    std::thread::sleep(std::time::Duration::from_millis(1000));
    
    #[allow(unused_mut)]
    let mut reputation = system.get_reputation_mut("validator1").unwrap();
    let expired = reputation.check_ban_status();
    assert!(expired, "check_ban_status deve indicar que o ban expirou");
    assert!(!reputation.is_banned, "is_banned interno deve ser false após expiração");
    assert!(!system.is_banned("validator1"), "Ban deve expirar após o tempo definido");
}

#[test]
fn test_reputation_serialization() {
    let mut system = ReputationSystem::new();
    system.add_validator("validator1".to_string());
    let rep = system.get_reputation_mut("validator1").unwrap();
    rep.ban(Duration::from_secs(3600));
    
    let serializable = rep.to_serializable();
    let serialized = serde_json::to_string(&serializable).unwrap();
    let deserialized: SerializableReputation = serde_json::from_str(&serialized).unwrap();
    let restored = ValidatorReputation::from_serializable(deserialized, Instant::now());
    
    assert_eq!(rep.validator_id, restored.validator_id);
    assert_eq!(rep.score, restored.score);
    assert!(restored.is_banned);
}