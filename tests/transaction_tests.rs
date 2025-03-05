//! # Testes de Transação
//!
//! Este arquivo contém testes de integração para o sistema de transações da blockchain.
//! Os testes validam o comportamento correto das transações, assinaturas e validação de dados.
//!
//! ## Estrutura de Testes
//!
//! - `test_transaction_validation`: Verifica se uma transação válida passa pela validação
//! - `test_invalid_amount`: Verifica se transações com valores acima do limite são rejeitadas
//! - `test_replay_attack`: Verifica se o sistema de proteção contra ataques de replay funciona
//! - `test_timestamp_validation`: Verifica se transações com timestamps inválidos são rejeitadas
//! - `test_address_validation`: Verifica a validação de endereços de origem e destino
//! - `test_signature_size`: Verifica se as assinaturas têm o tamanho correto
//! - `test_transaction_serialization`: Verifica a serialização de transações
//! - `test_signature_generation_and_size`: Verifica a geração e tamanho das assinaturas

use kybelith::constants;
use kybelith::constants::{MAX_AMOUNT, MAX_TRANSACTION_SIZE, MIN_ADDRESS_LENGTH};
use kybelith::error::TransactionError;
/// Cria uma transação válida para uso nos testes.
///
/// Esta função auxilia os testes ao criar uma transação completamente válida
/// com chaves geradas adequadamente e assinatura correta.
///
/// # Retorno
///
/// Retorna uma tupla contendo:
/// - A transação válida
/// - A chave privada usada para assinar
/// - A chave pública correspondente
// Importações corretas sem conflitos
use kybelith::transaction::{NonceRegistry, Transaction};
use pqcrypto_dilithium::dilithium5::{detached_sign, keypair, PublicKey, SecretKey};
use pqcrypto_traits::sign::DetachedSignature;
use pqcrypto_traits::sign::PublicKey as TraitsPublicKey; // Importado com um alias para evitar conflito
use serde::Serialize;

// Função auxiliar para serializar os dados da transação
// Já que serialize_for_signing é privado, precisamos recriá-lo aqui
fn serialize_transaction_for_signing(
    transaction: &Transaction,
) -> Result<Vec<u8>, TransactionError> {
    #[derive(Serialize)]
    struct SignableData<'a> {
        token_id: u64,
        from: &'a str,
        to: &'a str,
        amount: u64,
        timestamp: i64,
        nonce: u64,
        public_key: &'a [u8],
    }

    let data = SignableData {
        token_id: transaction.token_id,
        from: &transaction.from,
        to: &transaction.to,
        amount: transaction.amount,
        timestamp: transaction.timestamp,
        nonce: transaction.nonce,
        public_key: &transaction.public_key,
    };

    bincode::serialize(&data).map_err(|_| TransactionError::InvalidDataFormat)
}

/// Testa se uma transação válida passa pelo processo de validação.
///
/// Verifica:
/// - Se a transação é criada corretamente
/// - Se passa pela validação de nonce
/// - Se a assinatura é verificada corretamente
fn create_valid_transaction() -> Result<(Transaction, SecretKey, PublicKey), TransactionError> {
    // Usar a função keypair() de pqcrypto_dilithium para gerar chaves
    let (public_key, secret_key) = keypair();

    let mut transaction = Transaction::new(
        "a".repeat(MIN_ADDRESS_LENGTH),
        "b".repeat(MIN_ADDRESS_LENGTH),
        100,
        public_key.as_bytes().to_vec(),
    )?;

    // Usar a função auxiliar para serializar os dados
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    Ok((transaction, secret_key, public_key))
}

#[test]
fn test_transaction_validation() -> Result<(), TransactionError> {
    let (transaction, _, public_key) = create_valid_transaction()?;
    let mut nonce_registry = NonceRegistry::new();

    transaction.validate(&mut nonce_registry)?;
    transaction.verify(&public_key)?;

    Ok(())
}

/// Testa se transações com valores acima do limite são rejeitadas.
///
/// Este teste verifica se o sistema rejeita adequadamente transações
/// onde o valor excede o máximo permitido, garantindo que as regras
/// de negócio relacionadas a limites de valor sejam respeitadas.

#[test]
fn test_invalid_amount() -> Result<(), TransactionError> {
    let (mut transaction, secret_key, _) = create_valid_transaction()?;
    let mut nonce_registry = NonceRegistry::new();

    transaction.amount = MAX_AMOUNT + 1;

    // Precisamos atualizar a assinatura após mudar o amount
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    assert!(matches!(
        transaction.validate(&mut nonce_registry),
        Err(TransactionError::InvalidData(_))
    ));

    Ok(())
}

/// Testa a proteção contra ataques de replay.
///
/// Verifica se o sistema detecta e rejeita tentativas de reuso de transações,
/// o que é fundamental para segurança do blockchain contra ataques de replay
/// onde um atacante tenta reprocessar uma transação válida.

#[test]
fn test_replay_attack() -> Result<(), TransactionError> {
    let mut nonce_registry = NonceRegistry::new();
    let (transaction1, _, _) = create_valid_transaction()?;
    transaction1.validate(&mut nonce_registry)?;

    // Como Transaction não implementa Clone, precisamos criar uma nova transação
    // com os mesmos valores
    let mut transaction2 = Transaction::new(
        transaction1.from.clone(),
        transaction1.to.clone(),
        transaction1.amount,
        transaction1.public_key.clone(),
    )?;
    transaction2.signature = transaction1.signature.clone();
    transaction2.nonce = transaction1.nonce; // Usar o mesmo nonce para simular um ataque de replay
    transaction2.update_hash()?;

    assert!(matches!(
        transaction2.validate(&mut nonce_registry),
        Err(TransactionError::NonceOverflow)
    ));
    Ok(())
}

/// Testa a validação de timestamps.
///
/// Verifica se o sistema rejeita transações com timestamps inválidos,
/// como timestamps muito antigos ou no futuro, o que é importante
/// para manter a integridade temporal da blockchain.

#[test]
fn test_timestamp_validation() -> Result<(), TransactionError> {
    let (mut transaction, secret_key, _) = create_valid_transaction()?;

    // Definir um timestamp claramente inválido
    transaction.timestamp = 0;

    // Atualizar a assinatura após modificar o timestamp
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    // Ao invés de chamar validate_timestamp diretamente (que é privado),
    // usamos validate que internamente chama validate_timestamp
    let mut nonce_registry = NonceRegistry::new();
    let result = transaction.validate(&mut nonce_registry);

    // Verificar se o erro está relacionado ao timestamp
    assert!(matches!(result, Err(TransactionError::TimestampInvalid)));

    Ok(())
}

/// Testa a validação de endereços.
///
/// Verifica se o sistema valida corretamente os endereços de origem e destino,
/// garantindo que atendam aos requisitos de formato e tamanho.

#[test]
fn test_address_validation() -> Result<(), TransactionError> {
    let result = Transaction::new(
        "short".to_string(),
        "b".repeat(MIN_ADDRESS_LENGTH),
        100,
        vec![0; 32],
    );

    assert!(matches!(
        result,
        Err(TransactionError::AddressFormatInvalid)
    ));

    Ok(())
}

/// Testa o tamanho das assinaturas.
///
/// Verifica se as assinaturas geradas estão dentro dos limites de tamanho
/// esperados para o algoritmo criptográfico usado (Dilithium5).

#[test]
fn test_signature_size() -> Result<(), TransactionError> {
    let (transaction, _, _) = create_valid_transaction()?;

    // Verificar se o tamanho está dentro dos limites esperados para Dilithium5
    assert!(
        !transaction.signature.is_empty() && transaction.signature.len() <= 4627,
        "Signature size is out of expected bounds"
    );

    Ok(())
}

/// Testa a serialização de transações.
///
/// Verifica se a serialização de transações para assinatura funciona corretamente,
/// garantindo que os dados serializados não estejam vazios e não excedam o tamanho máximo.

#[test]
fn test_transaction_serialization() -> Result<(), TransactionError> {
    let (transaction, _, _) = create_valid_transaction()?;
    let data = serialize_transaction_for_signing(&transaction)?;
    assert!(!data.is_empty());
    assert!(data.len() <= MAX_TRANSACTION_SIZE);
    Ok(())
}

/// Testa a geração e tamanho de assinaturas.
///
/// Verifica:
/// - Se novas assinaturas podem ser geradas corretamente
/// - Se o tamanho da assinatura está dentro dos limites
/// - Se a assinatura pode ser verificada com sucesso

#[test]
fn test_signature_generation_and_size() -> Result<(), TransactionError> {
    let (mut transaction, secret_key, public_key) = create_valid_transaction()?;

    // Limpa a assinatura existente e assina novamente
    transaction.signature.clear();

    // Usa detached_sign para gerar a assinatura
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    // Verifica se a assinatura tem o tamanho esperado para Dilithium5
    assert!(
        transaction.signature.len() <= 4627,
        "Signature size is larger than expected"
    );

    // Verifica se a assinatura é válida
    transaction.verify(&public_key)?;
    Ok(())
}

// Adicione estes testes ao seu arquivo tests/transaction_tests.rs

/// Testa a rejeição de transações quando a assinatura é inválida.
///
/// Este teste verifica se o sistema rejeita transações cuja assinatura
/// não corresponde ao conteúdo, simulando um cenário de manipulação de dados.

#[test]
fn test_invalid_signature() -> Result<(), TransactionError> {
    let (mut transaction, _, public_key) = create_valid_transaction()?;

    // Alterando a assinatura para torná-la inválida
    if !transaction.signature.is_empty() {
        transaction.signature[0] = transaction.signature[0].wrapping_add(1);
    }

    // A verificação deve falhar
    assert!(transaction.verify(&public_key).is_err());

    Ok(())
}

/// Testa a rejeição de transações quando o endereço de destino é igual ao de origem.
///
/// Verifica se o sistema impede transações onde o remetente e o destinatário são idênticos,
/// o que pode indicar um erro ou tentativa de ataque.

#[test]
fn test_same_address() -> Result<(), TransactionError> {
    let addr = "a".repeat(MIN_ADDRESS_LENGTH);

    let result = Transaction::new(addr.clone(), addr, 100, vec![0; 32]);

    match result {
        Ok(transaction) => {
            // Se a transação foi criada, vamos verificar se falha na validação
            let mut nonce_registry = NonceRegistry::new();
            let validation_result = transaction.validate(&mut nonce_registry);
            assert!(
                validation_result.is_err(),
                "Transação com mesmo endereço de origem e destino deveria falhar na validação"
            );
        }
        Err(err) => {
            // Se falhar na criação, é aceitável também
            println!("Transação com mesmo endereço falhou na criação: {:?}", err);
        }
    }

    Ok(())
}

/// Testa a rejeição de transações com valor zero.
///
/// Verifica se o sistema rejeita transações com valor zero,
/// imperdindo transações que não movimentam fundos.

#[test]
fn test_zero_amount() -> Result<(), TransactionError> {
    // Criar uma transação com amount = 0
    let result = Transaction::new(
        "a".repeat(MIN_ADDRESS_LENGTH),
        "b".repeat(MIN_ADDRESS_LENGTH),
        0, // Valor zero
        vec![0; 32],
    );

    // Se MIN_AMOUNT > 0, isso deve gerar um erro
    if crate::constants::MIN_AMOUNT > 0 {
        let mut nonce_registry = NonceRegistry::new();
        match result {
            Ok(transaction) => {
                assert!(matches!(
                    transaction.validate(&mut nonce_registry),
                    Err(TransactionError::InvalidData(_))
                ));
            }
            Err(e) => {
                // Também é válido se a criação já falhar diretamente
                assert!(matches!(e, TransactionError::InvalidData(_)));
            }
        }
    }

    Ok(())
}

/// Testa a validação de nonce quando ocorre um salto muito grande.
///
/// Verifica se o sistema rejeita transações onde o nonce é muito maior
/// que o último nonce conhecido, o que pode indicar um possível ataque.

#[test]
fn test_nonce_gap_too_large() -> Result<(), TransactionError> {
    let mut nonce_registry = NonceRegistry::new();
    let (transaction1, _, _) = create_valid_transaction()?;

    // Registrar o primeiro nonce
    transaction1.validate(&mut nonce_registry)?;

    // Criar uma nova transação com um nonce muito grande
    let (mut transaction2, secret_key, _) = create_valid_transaction()?;
    transaction2.nonce = 99999; // Um valor presumivelmente maior que max_nonce_gap

    // Assinar novamente após alterar o nonce
    let data = serialize_transaction_for_signing(&transaction2)?;
    let signature = detached_sign(&data, &secret_key);
    transaction2.signature = signature.as_bytes().to_vec();
    transaction2.update_hash()?;

    // Deve falhar na validação
    let result = transaction2.validate(&mut nonce_registry);
    assert!(matches!(result, Err(TransactionError::InvalidData(_))));

    Ok(())
}

/// Testa a rejeição de transações com chaves públicas inválidas.
///
/// Verifica se o sistema detecta e rejeita transações onde a chave pública
/// não é válida ou está corrompida.

#[test]
fn test_invalid_public_key() -> Result<(), TransactionError> {
    let (mut transaction, secret_key, _) = create_valid_transaction()?;

    // Corromper a chave pública
    if !transaction.public_key.is_empty() {
        transaction.public_key[0] = transaction.public_key[0].wrapping_add(1);
    }

    // Assinar novamente
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    // Gerar uma nova chave pública para verificação
    let (new_public_key, _) = keypair();

    // A verificação deve falhar
    assert!(transaction.verify(&new_public_key).is_err());

    Ok(())
}

/// Testa o limite de tamanho máximo da transação.
///
/// Verifica se o sistema rejeita transações que excedem o tamanho máximo permitido,
/// o que é importante para evitar ataques de DoS.
#[test]
fn test_transaction_size_limit() -> Result<(), TransactionError> {
    let (mut transaction, secret_key, _) = create_valid_transaction()?;

    // Adicionar dados grandes para ultrapassar o limite de tamanho
    // (Isso pode não funcionar dependendo de como a validação é implementada)
    transaction.from = "a".repeat(1024 * 1024); // 1MB de dados
    transaction.to = "b".repeat(1024 * 1024); // 1MB de dados

    // Assinar novamente
    let data = serialize_transaction_for_signing(&transaction)?;
    let signature = detached_sign(&data, &secret_key);
    transaction.signature = signature.as_bytes().to_vec();
    transaction.update_hash()?;

    // Deve falhar em algum ponto (criação, serialização ou validação)
    let mut nonce_registry = NonceRegistry::new();
    let result = transaction.validate(&mut nonce_registry);

    assert!(result.is_err());

    Ok(())
}
