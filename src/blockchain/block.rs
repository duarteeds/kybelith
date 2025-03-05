use crate::error::Error;
use crate::smart_contract::SmartContract;
use crate::transaction::SecureTransaction;
use pqcrypto_dilithium::dilithium5;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

// Constantes
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024; // 1MB
pub const MAX_FUTURE_TIME_DRIFT: u64 = 3600; // 1 hora
pub const MAX_PAST_TIME_DRIFT: u64 = 7200; // 2 horas

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<SecureTransaction>,
    pub contracts: Vec<SmartContract>,
    pub previous_hash: String,
    pub hash: String,
    pub validator_signature: Option<Vec<u8>>,
    pub nonce: u64,
    pub processed_transactions: HashSet<String>,
}

impl Block {
    pub fn new(
        index: u64,
        transactions: Vec<SecureTransaction>,
        contracts: Vec<SmartContract>,
        previous_hash: String,
    ) -> Result<Self, Error> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hash =
            Self::calculate_hash(index, timestamp, &transactions, &contracts, &previous_hash)?;

        Ok(Block {
            index,
            timestamp,
            transactions,
            contracts,
            previous_hash,
            hash,
            validator_signature: None,
            nonce: 0,
            processed_transactions: HashSet::new(),
        })
    }

    pub fn size(&self) -> usize {
        let mut size = 0;

        // Tamanho do índice (u64 = 8 bytes)
        size += 8;

        // Tamanho do timestamp (u64 = 8 bytes)
        size += 8;

        // Tamanho do previous_hash (String)
        size += self.previous_hash.len();

        // Tamanho do hash (String)
        size += self.hash.len();

        // Tamanho das transações
        for tx in &self.transactions {
            size += tx.size(); // Supondo que Transaction também tenha um método size()
        }

        // Tamanho dos contratos (se houver)
        for contract in &self.contracts {
            size += contract.size(); // Supondo que Contract também tenha um método size()
        }

        // Tamanho do nonce (u64 = 8 bytes)
        size += 8;

        // Tamanho do validator_signature (se houver)
        if let Some(signature) = &self.validator_signature {
            size += signature.len();
        }

        size
    }

    pub fn validate_block(&self, public_key: &dilithium5::PublicKey) -> Result<(), Error> {
        if self.size() > MAX_BLOCK_SIZE {
            return Err(Error::BlockTooLarge);
        }

        if !self.validate_previous_hash()? {
            return Err(Error::InvalidPreviousHash);
        }

        self.verify_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InvalidTimestamp("Falha ao obter o tempo atual".to_string()))?
                .as_secs() as i64,
        )?;

        for tx in &self.transactions {
            tx.verify(public_key, &tx.signature)?;
        }

        Ok(())
    }

    fn verify_timestamp(&self, current_time: i64) -> Result<(), Error> {
        let timestamp_u64 = self.timestamp as u64;

        if timestamp_u64 > (current_time as u64 + MAX_FUTURE_TIME_DRIFT) {
            return Err(Error::InvalidTimestamp("Timestamp no futuro".to_string()));
        }

        if (current_time as u64) > (timestamp_u64 + MAX_PAST_TIME_DRIFT) {
            return Err(Error::StaleBlock);
        }

        Ok(())
    }

    fn validate_previous_hash(&self) -> Result<bool, Error> {
        let block_data = format!(
            "{}:{}:{}:{}",
            self.index,
            self.timestamp,
            self.transactions.len(), // Usar o número de transações em vez de serializá-las
            self.previous_hash
        );

        let current_hash = Self::calculate_quantum_hash(&block_data)?;
        Ok(current_hash.as_slice().ct_eq(self.hash.as_bytes()).into())
    }

    fn calculate_quantum_hash(data: &str) -> Result<Vec<u8>, Error> {
        let mut hasher = Sha3_256::new();
        hasher.update(data.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    pub fn calculate_hash(
        index: u64,
        timestamp: u64,
        transactions: &Vec<SecureTransaction>,
        contracts: &Vec<SmartContract>,
        previous_hash: &str,
    ) -> Result<String, Error> {
        let data = format!(
            "{}:{}:{}:{}:{}",
            index,
            timestamp,
            transactions.len(),
            contracts.len(),
            previous_hash
        );
        let hash = Self::calculate_quantum_hash(&data)?;
        Ok(hex::encode(hash))
    }
}
