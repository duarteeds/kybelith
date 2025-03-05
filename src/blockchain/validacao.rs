use crate::blockchain::block::Block;
use crate::blockchain::Blockchain;
use crate::constants::{MAX_TIME_DRIFT, MAX_TRANSACTION_SIZE};
use crate::error::Error;
use crate::error::TransactionError;
use crate::transaction::Transaction;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

impl Default for Validator {
    fn default() -> Self {
        Self {
            max_transaction_size: 128 * 1024, // 128KB
            max_time_drift: 300,              // 5 minutos
        }
    }
}

// Definir o enum ValidationError

#[derive(Debug)]
pub enum ValidationError {
    BlockTooLarge,
    TimestampTooFar,
    TimestampTooOld,
    InvalidPreviousHash,
    InvalidSignature,
    DataSizeExceeded,
    InvalidFormat,
}

// Definir a struct Validator
#[derive(Debug)]
pub struct Validator {
    max_transaction_size: usize,
    max_time_drift: i64,
}

impl Validator {
    pub fn new(max_transaction_size: usize, max_time_drift: i64) -> Self {
        Self {
            max_transaction_size,
            max_time_drift,
        }
    }

    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        blockchain: &Blockchain,
        current_nonce: u64,
    ) -> Result<(), Error> {
        // Validar formato dos endereços
        if !self.validate_address_format(&tx.from) || !self.validate_address_format(&tx.to) {
            return Err(Error::InvalidInput("Endereço inválido".to_string()));
        }

        // Validar token
        let _token = blockchain
            .get_token(&tx.token_id.to_string())
            .ok_or(Error::InvalidInput("Token não encontrado".to_string()))?;

        // Validar nonce
        if tx.nonce != current_nonce + 1 {
            return Err(Error::InvalidNonce);
        }

        // Validar valor
        if tx.amount == 0 {
            return Err(Error::InvalidInput("Valor inválido".to_string()));
        }

        // Validar timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidTimestamp("Erro ao obter timestamp".to_string()))?
            .as_secs() as i64;

        if tx.timestamp < current_time - 86400 || tx.timestamp > current_time + self.max_time_drift
        {
            return Err(Error::InvalidTimestamp(
                "Timestamp fora do intervalo permitido".to_string(),
            ));
        }

        // Validar tamanho da transação
        let tx_size = bincode::serialize(tx)
            .map_err(|_| Error::InvalidFormat("Erro na serialização".to_string()))?
            .len();

        if tx_size > self.max_transaction_size {
            return Err(Error::BlockTooLarge);
        }

        // Verificar se a transação é duplicada
        if blockchain.transaction_exists(tx) {
            return Err(Error::InvalidInput("Transação duplicada".to_string()));
        }

        // Validar assinatura
        if !self.verify_signature_with_delay(tx)? {
            return Err(Error::InvalidInput("Assinatura inválida".to_string()));
        }

        Ok(())
    }

    pub fn validate_block(
        &self,
        block: &Block,
        blockchain: &Blockchain,
    ) -> Result<(), ValidationError> {
        // Validação de tamanho
        if block.size() > self.max_transaction_size {
            return Err(ValidationError::BlockTooLarge);
        }

        // Validação de timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if block.timestamp > (current_time + self.max_time_drift) as u64 {
            return Err(ValidationError::TimestampTooFar);
        }

        if block.timestamp < (current_time - self.max_time_drift) as u64 {
            return Err(ValidationError::TimestampTooOld);
        }

        // Validação de hash anterior
        if !blockchain.chain.is_empty() {
            let last_block = blockchain.chain.last().unwrap();
            if block.previous_hash != last_block.hash {
                return Err(ValidationError::InvalidPreviousHash);
            }
        }

        Ok(())
    }

    pub fn is_timestamp_valid(&self, timestamp: i64, current_time: i64) -> bool {
        let future_drift = current_time + self.max_time_drift;
        let past_drift = current_time - self.max_time_drift;

        timestamp <= future_drift && timestamp >= past_drift
    }

    fn validate_address_format(&self, address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }

        if address.len() != 42 {
            return false;
        }

        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    fn verify_signature_with_delay(&self, tx: &Transaction) -> Result<bool, Error> {
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let result = self.verify_signature(tx)?;
        let elapsed = start.elapsed();

        // Adicionar delay aleatório para mitigar timing attacks
        if elapsed < Duration::from_millis(100) {
            let mut rng = rand::thread_rng();
            std::thread::sleep(Duration::from_millis(rng.gen_range(0..100)));
        }

        Ok(result)
    }

    fn verify_signature(&self, tx: &Transaction) -> Result<bool, Error> {
        let pk = dilithium5::PublicKey::from_bytes(&tx.public_key)
            .map_err(|_| Error::InvalidInput("Chave pública inválida".to_string()))?;
        let sig = dilithium5::DetachedSignature::from_bytes(&tx.signature)
            .map_err(|_| Error::InvalidInput("Assinatura inválida".to_string()))?;

        let data = format!("{}:{}:{}:{}", tx.from, tx.to, tx.amount, tx.timestamp);

        Ok(dilithium5::verify_detached_signature(&sig, data.as_bytes(), &pk).is_ok())
    }
}

// Funções utilitárias
pub fn validate_timestamp(timestamp: i64, current_time: i64) -> bool {
    timestamp <= (current_time + MAX_TIME_DRIFT) && timestamp >= (current_time - MAX_TIME_DRIFT)
}

pub fn validate_transaction_size(tx: &Transaction) -> Result<(), TransactionError> {
    if tx.size() > MAX_TRANSACTION_SIZE {
        return Err(TransactionError::DataSizeExceeded);
    }
    Ok(())
}

pub fn validate_address_format(address: &str) -> bool {
    if address.len() < 32 || address.len() > 64 {
        return false;
    }

    // Verifica se o endereço contém apenas caracteres válidos
    address.chars().all(|c| c.is_alphanumeric())
}

// Corrigir para usar o tipo TransactionError correto
pub fn verify_signature_with_delay(
    tx: &Transaction,
    public_key: &dilithium5::PublicKey,
) -> Result<(), TransactionError> {
    // Adiciona um pequeno atraso para mitigar ataques de timing
    std::thread::sleep(std::time::Duration::from_millis(5));

    // Você precisa implementar um adaptador que converte o tipo de erro
    match tx.verify(public_key) {
        Ok(()) => Ok(()),
        Err(_) => Err(TransactionError::InvalidSignature(
            "Assinatura inválida".to_string(),
        )),
    }
}
