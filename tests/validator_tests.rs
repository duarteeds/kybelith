use kybelith::consensus::validator::{Validator, ValidatorSet, ValidatorSetConfig};
use kybelith::consensus::reputation::ReputationSystem;
use kybelith::consensus::ReputationAction;

fn create_test_validator(id: &str, stake: u64) -> Validator {
    Validator::new(
        id.to_string(),
        format!("127.0.0.1:{}", 8000 + id.parse::<u16>().unwrap_or(0)),
        vec![0, 1, 2, 3], // Dummy public key
        stake,
    )
}

#[test]
fn test_validator_creation() {
    let validator = create_test_validator("1", 1000);
    
    assert_eq!(validator.id, "1");
    assert_eq!(validator.stake, 1000);
    assert!(validator.is_active);
    assert_eq!(validator.last_proposed_block, None);
}

#[test]
fn test_validator_eligibility() {
    let mut validator = create_test_validator("1", 1000);
    
    // Sem proposta anterior, deve ser elegível
    assert!(validator.is_eligible_to_propose(100, 10));
    
    // Definir última proposta
    validator.last_proposed_block = Some(90);
    
    // Não é elegível ainda (dentro do cooldown)
    assert!(!validator.is_eligible_to_propose(95, 10));
    
    // Elegível após o cooldown
    assert!(validator.is_eligible_to_propose(101, 10));
    
    // Validador inativo não deve ser elegível
    validator.is_active = false;
    assert!(!validator.is_eligible_to_propose(101, 10));
}

#[test]
fn test_validator_set_add_remove() {
    let config = ValidatorSetConfig {
        min_validators: 3,
        min_stake: 1000,
        proposer_cooldown: 10,
    };
    let mut validator_set = ValidatorSet::with_config(Vec::new(), config);
    let validator1 = create_test_validator("1", 1001); // > min_stake
    let validator2 = create_test_validator("2", 2000);
    let validator3 = create_test_validator("3", 500);
    let added = validator_set.add_validator(validator1.clone());
    assert!(added, "Deve adicionar validator1");
    assert!(validator_set.add_validator(validator2.clone()));
    assert!(!validator_set.add_validator(validator3.clone()));
    assert_eq!(validator_set.len(), 2);
    assert!(validator_set.contains("1"));
    assert!(validator_set.contains("2"));
    assert!(!validator_set.contains("3"));
    assert!(validator_set.remove_validator("1"));
    assert_eq!(validator_set.len(), 1);
    assert!(!validator_set.contains("1"));
    assert!(!validator_set.remove_validator("99"));
}

#[test]
fn test_validator_set_quorum() {
    let config = ValidatorSetConfig {
        min_validators: 3,
        min_stake: 1000,
        proposer_cooldown: 10,
    };
    
    let mut validator_set = ValidatorSet::with_config(Vec::new(), config);
    
    // Adiciona 2 validadores (menos que o mínimo)
    validator_set.add_validator(create_test_validator("1", 1000));
    validator_set.add_validator(create_test_validator("2", 2000));
    
    assert!(!validator_set.has_quorum());
    
    // Adiciona mais um validador para atingir o quórum
    validator_set.add_validator(create_test_validator("3", 1500));
    
    assert!(validator_set.has_quorum());
    
    // Marca um validador como inativo
    let _ = validator_set.set_validator_active("1", false);
    
    assert!(!validator_set.has_quorum());
}

#[test]
fn test_stake_weighted_selection() {
    let config = ValidatorSetConfig {
        min_validators: 1,
        min_stake: 1000,
        proposer_cooldown: 10,
    };
    
    let mut validator_set = ValidatorSet::with_config(Vec::new(), config);
    
    // Adiciona validadores com diferentes stakes
    validator_set.add_validator(create_test_validator("1", 1000));  // 1/6 do stake total
    validator_set.add_validator(create_test_validator("2", 5000));  // 5/6 do stake total
    
    // Simula múltiplas seleções e conta as ocorrências
    let mut counts = std::collections::HashMap::new();
    
    for height in 1..1001 {
        let proposer = validator_set.select_proposer_stake_weighted(height).unwrap();
        *counts.entry(proposer.id.clone()).or_insert(0) += 1;
    }
    
    // Validador "2" deve ser selecionado aproximadamente 5 vezes mais que validador "1"
    // Consideramos uma margem de erro para aleatoriedade
    let ratio = *counts.get("2").unwrap_or(&0) as f64 / *counts.get("1").unwrap_or(&1) as f64;
    
    assert!(ratio > 3.0, "Validador com mais stake deve ser selecionado mais frequentemente");
    assert!(ratio < 7.0, "A razão de seleção deve estar próxima da razão de stake");
}

#[test]
fn test_round_robin_selection() {
    let config = ValidatorSetConfig {
        min_validators: 1,
        min_stake: 1000,
        proposer_cooldown: 10,
    };
    
    let mut validator_set = ValidatorSet::with_config(Vec::new(), config);
    
    // Adiciona validadores
    validator_set.add_validator(create_test_validator("1", 1000));
    validator_set.add_validator(create_test_validator("2", 5000));
    validator_set.add_validator(create_test_validator("3", 3000));
    
    // Verifica se a seleção é round-robin
    let proposer1 = validator_set.select_proposer_round_robin(1).unwrap();
    let proposer2 = validator_set.select_proposer_round_robin(2).unwrap();
    let proposer3 = validator_set.select_proposer_round_robin(3).unwrap();
    let proposer4 = validator_set.select_proposer_round_robin(4).unwrap();
    
    assert_ne!(proposer1.id, proposer2.id);
    assert_ne!(proposer2.id, proposer3.id);
    assert_eq!(proposer1.id, proposer4.id); // Volta ao início após percorrer todos
}

#[test]
fn test_weighted_selection_with_reputation() {
    let config = ValidatorSetConfig {
        min_validators: 1,
        min_stake: 1000,
        proposer_cooldown: 10,
    };
    
    let mut validator_set = ValidatorSet::with_config(Vec::new(), config);
    
    // Adiciona validadores com mesmo stake
    validator_set.add_validator(create_test_validator("1", 3000));
    validator_set.add_validator(create_test_validator("2", 3000));
    
    // Cria sistema de reputação com diferenças
    let mut reputation = ReputationSystem::new();
    reputation.add_validator("1".to_string());
    reputation.add_validator("2".to_string());
    
    // Configura reputações diferentes
    // Validador 1: reputação neutra (50.0)
    // Validador 2: reputação alta (80.0)
    let _ = reputation.update_reputation("2", ReputationAction::ValidBlockProposed);
    let _ = reputation.update_reputation("2", ReputationAction::ValidBlockProposed);
    let _ = reputation.update_reputation("2", ReputationAction::ValidBlockProposed);
    let _ = reputation.update_reputation("2", ReputationAction::CorrectVote);
    let _ = reputation.update_reputation("2", ReputationAction::CorrectVote);
    
    // Simula múltiplas seleções e conta as ocorrências
    let mut counts = std::collections::HashMap::new();
    
    for height in 1..1001 {
        let proposer = validator_set.select_proposer_weighted(height, &reputation).unwrap();
        *counts.entry(proposer.id.clone()).or_insert(0) += 1;
    }
    
    // Validador "2" com maior reputação deve ser selecionado mais frequentemente
    let count1 = *counts.get("1").unwrap_or(&0);
    let count2 = *counts.get("2").unwrap_or(&0);
    
    assert!(count2 > count1, "Validador com maior reputação deve ser selecionado mais frequentemente");
    println!("Contagem de seleções - Validador 1: {}, Validador 2: {}", count1, count2);
}