use crate::constants::MAX_SIGNATURE_SIZE;
use crate::constants::{HASH_SALT, MAX_ADDRESS_LENGTH, MIN_ADDRESS_LENGTH, TIMESTAMP_WINDOW};
use crate::constants::{MAX_AMOUNT, MIN_AMOUNT};
use crate::error::TransactionError;
use crate::transaction::secure_transaction::SecureTransaction;
use bincode::serialize;
use once_cell::sync::Lazy;
use pqcrypto_dilithium::dilithium5::verify_detached_signature;
use pqcrypto_dilithium::dilithium5::{keypair, sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::DetachedSignature as PqcDetachedSignature;
use pqcrypto_traits::sign::SignedMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::warn;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Zeroize, Clone)]
pub struct Transaction {
    pub token_id: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: i64,
    pub nonce: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    pub hash: String,
}

impl From<SecureTransaction> for Transaction {
    fn from(st: SecureTransaction) -> Self {
        let mut transaction = Transaction {
            token_id: 0,
            from: st.from.clone(),
            to: st.to.clone(),
            amount: st.amount,
            timestamp: st.timestamp,
            nonce: st.nonce,
            public_key: Vec::new(),
            signature: Vec::new(),
            transaction_hash: Vec::new(),
            hash: String::new(),
        };
        let _ = transaction.update_hash();
        transaction
    }
}

pub struct NonceRegistry {
    registry: Mutex<HashMap<String, u64>>,
    max_nonce_gap: u64,
    last_update: Mutex<HashMap<String, i64>>,
    min_update_interval: i64,
}

impl NonceRegistry {
    pub fn new() -> Self {
        NonceRegistry {
            registry: Mutex::new(HashMap::new()),
            max_nonce_gap: 1000,
            last_update: Mutex::new(HashMap::new()),
            min_update_interval: 1,
        }
    }

    pub fn validate_nonce(&mut self, address: &str, nonce: u64) -> Result<(), TransactionError> {
        let registry = self.registry.get_mut().unwrap();
        let last_nonce = registry.get(address).copied().unwrap_or(0);

        // Verificar se o nonce está dentro da gap permitida
        if nonce > last_nonce + self.max_nonce_gap {
            return Err(TransactionError::InvalidData(
                "Nonce gap excedida".to_string(),
            ));
        }

        if nonce <= last_nonce {
            return Err(TransactionError::NonceOverflow);
        }

        // Verificar o intervalo mínimo de atualização
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TransactionError::TimestampInvalid)?
            .as_secs() as i64;

        let mut last_update_map = self.last_update.lock().unwrap();
        if let Some(last_time) = last_update_map.get(address) {
            if now - last_time < self.min_update_interval {
                return Err(TransactionError::InvalidData(
                    "Intervalo de atualização muito pequeno".to_string(),
                ));
            }
        }

        registry.insert(address.to_string(), nonce);
        last_update_map.insert(address.to_string(), now);
        Ok(())
    }
}

impl Transaction {
    pub fn new(
        from: String,
        to: String,
        amount: u64,
        public_key: Vec<u8>,
    ) -> Result<Self, TransactionError> {
        if from.len() < MIN_ADDRESS_LENGTH
            || from.len() > MAX_ADDRESS_LENGTH
            || to.len() < MIN_ADDRESS_LENGTH
            || to.len() > MAX_ADDRESS_LENGTH
        {
            return Err(TransactionError::AddressFormatInvalid);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TransactionError::TimestampInvalid)?
            .as_secs() as i64;

        let mut transaction = Transaction {
            token_id: 0,
            from,
            to,
            amount,
            timestamp,
            nonce: 1,
            hash: String::new(),
            public_key,
            signature: Vec::new(),
            transaction_hash: Vec::new(),
        };

        transaction.update_hash()?;
        Ok(transaction)
    }

    pub fn validate(&self, nonce_registry: &mut NonceRegistry) -> Result<(), TransactionError> {
        use crate::constants::{MAX_SIGNATURE_SIZE, MAX_TRANSACTION_SIZE}; // Remova TIMESTAMP_WINDOW daqui

        if self.amount < MIN_AMOUNT || self.amount > MAX_AMOUNT {
            return Err(TransactionError::InvalidData(
                "Valor de transação inválido".to_string(),
            ));
        }

        self.validate_address()?;

        // Validação de timestamp
        self.validate_timestamp()?;

        // Validação de tamanho de assinatura
        if self.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(TransactionError::SignatureSizeExceeded);
        }

        // Validação de nonce
        nonce_registry.validate_nonce(&self.from, self.nonce)?;

        // Verificação de tamanho total da transação
        if serialize(self)
            .map_err(|_| TransactionError::InvalidDataFormat)?
            .len()
            > MAX_TRANSACTION_SIZE
        {
            return Err(TransactionError::DataSizeExceeded);
        }

        Ok(())
    }

    pub fn validate_address(&self) -> Result<(), TransactionError> {
        let re = Regex::new(&format!(
            "^[a-zA-Z0-9]{{{},{}}}$",
            MIN_ADDRESS_LENGTH, MAX_ADDRESS_LENGTH
        ))
        .map_err(|_| TransactionError::AddressFormatInvalid)?;

        if !re.is_match(&self.from) || !re.is_match(&self.to) {
            return Err(TransactionError::AddressFormatInvalid);
        }

        if self.from == self.to {
            return Err(TransactionError::AddressFormatInvalid);
        }

        Ok(())
    }

    pub fn validate_input(&self, input: &[u8]) -> Result<(), TransactionError> {
        const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB

        if input.len() > MAX_INPUT_SIZE {
            return Err(TransactionError::InvalidInput(
                "Input excede tamanho máximo".into(),
            ));
        }

        if !input.iter().all(|&byte| byte.is_ascii()) {
            return Err(TransactionError::InvalidFormat(
                "Input contém caracteres inválidos".into(),
            ));
        }

        Ok(())
    }

    pub fn validate_timestamp(&self) -> Result<(), TransactionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TransactionError::TimestampInvalid)?
            .as_secs() as i64;

        match now.checked_sub(self.timestamp) {
            Some(diff) if diff.abs() <= TIMESTAMP_WINDOW => Ok(()),
            _ => {
                warn!("Timestamp inválido detectado. From: {}", self.from);
                Err(TransactionError::TimestampInvalid)
            }
        }
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result<(), TransactionError> {
        let data = self.serialize_for_signing()?;

        // Validate signature size before attempting conversion
        if self.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(TransactionError::SignatureSizeExceeded);
        }

        let signature =
            pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(&self.signature)
                .map_err(|_| {
                    TransactionError::InvalidSignatures("Invalid signature".to_string())
                })?;

        verify_detached_signature(&signature, &data, public_key)
            .map_err(|_| TransactionError::InvalidSignatures("Invalid signature".to_string()))?;

        Ok(())
    }

    pub fn size(&self) -> usize {
        let mut size = 0;
        size += self.from.len();
        size += self.to.len();
        size += self.hash.len();
        size += 8 * 4; // token_id, amount, timestamp, nonce
        size += self.public_key.len();
        size += self.signature.len();
        size += self.transaction_hash.len();
        size
    }

    pub fn serialize_for_signing(&self) -> Result<Vec<u8>, TransactionError> {
        #[derive(Serialize)]
        struct SignableData {
            token_id: u64,
            from: String,
            to: String,
            amount: u64,
            timestamp: i64,
            nonce: u64,
            public_key: Vec<u8>,
        }

        let data = SignableData {
            token_id: self.token_id,
            from: self.from.clone(),
            to: self.to.clone(),
            amount: self.amount,
            timestamp: self.timestamp,
            nonce: self.nonce,
            public_key: self.public_key.clone(),
        };

        bincode::serialize(&data).map_err(|_| TransactionError::InvalidDataFormat)
    }

    fn calculate_hash(&self) -> Result<Vec<u8>, TransactionError> {
        #[derive(Serialize)]
        struct TransactionHashData<'a> {
            token_id: u64,
            from: &'a str,
            to: &'a str,
            amount: u64,
            timestamp: i64,
            nonce: u64,
            public_key: &'a [u8],
            salt: &'a [u8],
            signature: &'a [u8],
        }

        let hash_data = TransactionHashData {
            token_id: self.token_id,
            from: &self.from,
            to: &self.to,
            amount: self.amount,
            timestamp: self.timestamp,
            nonce: self.nonce,
            public_key: &self.public_key,
            salt: HASH_SALT,
            signature: &self.signature,
        };

        let data = serialize(&hash_data).map_err(|_| TransactionError::InvalidDataFormat)?;
        static HASH_KEYS: Lazy<(PublicKey, SecretKey)> = Lazy::new(|| keypair());
        let signature = sign(&data, &HASH_KEYS.1);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn update_hash(&mut self) -> Result<(), TransactionError> {
        self.transaction_hash = self.calculate_hash()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Zeroize)]
pub struct TransactionBuilder {
    pub token_id: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: i64,
    pub nonce: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    pub hash: String,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            token_id: 0,
            from: String::new(),
            to: String::new(),
            amount: 0,
            timestamp: 0,
            nonce: 0,
            public_key: Vec::new(),
            signature: Vec::new(),
            transaction_hash: Vec::new(),
            hash: String::new(),
        }
    }

    pub fn token_id(mut self, token_id: u64) -> Self {
        self.token_id = token_id;
        self
    }

    pub fn from(mut self, from: String) -> Self {
        self.from = from;
        self
    }

    pub fn to(mut self, to: String) -> Self {
        self.to = to;
        self
    }

    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = amount;
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key = public_key;
        self
    }

    pub fn build(self) -> Result<Transaction, TransactionError> {
        Transaction::new(self.from, self.to, self.amount, self.public_key)
    }
}
