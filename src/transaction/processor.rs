use super::builder::{NonceRegistry, Transaction};
use crate::constants::{MAX_AMOUNT, MAX_SIGNATURE_SIZE, MIN_AMOUNT, TIMESTAMP_WINDOW};
use crate::error::TransactionError;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::Mutex;

// Variável global para armazenar nonces usados
static USED_NONCES: Lazy<Mutex<HashSet<Vec<u8>>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub struct TransactionProcessor;

impl TransactionProcessor {
    pub fn validate(
        &self,
        transaction: &Transaction,
        nonce_registry: &mut NonceRegistry,
    ) -> Result<(), TransactionError> {
        if transaction.amount < MIN_AMOUNT || transaction.amount > MAX_AMOUNT {
            return Err(TransactionError::InvalidData(
                "Valor de transação inválido".to_string(),
            ));
        }

        transaction.validate_address()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TransactionError::TimestampInvalid)?
            .as_secs() as i64;

        if (now - transaction.timestamp).abs() > TIMESTAMP_WINDOW {
            return Err(TransactionError::TimestampInvalid);
        }

        if transaction.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(TransactionError::SignatureSizeExceeded);
        }

        nonce_registry.validate_nonce(&transaction.from, transaction.nonce)?;

        Ok(())
    }

    pub fn verify_nonce(&self, nonce: &[u8]) -> Result<(), TransactionError> {
        let mut nonces = USED_NONCES
            .lock()
            .map_err(|_| TransactionError::LockError)?;

        if nonces.contains(nonce) {
            return Err(TransactionError::NonceReused);
        }

        nonces.insert(nonce.to_vec());
        Ok(())
    }
}
