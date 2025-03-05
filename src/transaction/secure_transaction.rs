use crate::error::TransactionError;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_dilithium::dilithium5::{detached_sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::{
    DetachedSignature as PqcDetachedSignature, PublicKey as TraitsPublicKey,
};
use secrecy::Zeroize;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;

const MAX_SIGNATURE_SIZE: usize = 4627; // Tamanho da assinatura Dilithium5

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
pub struct SecureTransaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: i64,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub cipher_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
    pub mac: Vec<u8>,
}

impl SecureTransaction {
    pub fn new(
        from: String,
        to: String,
        amount: u64,
        timestamp: i64,
        nonce: u64,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<Self, TransactionError> {
        // Gera salt e IV aleatórios
        let salt = secretbox::gen_nonce().0.to_vec();
        let iv = secretbox::gen_nonce().0.to_vec();

        // Gera chave de cifra
        let cipher_key = secretbox::gen_key().0.to_vec();

        // Cria a transação inicial
        let mut transaction = SecureTransaction {
            from,
            to,
            amount,
            timestamp,
            nonce,
            signature: Vec::new(),
            public_key: public_key.as_bytes().to_vec(),
            cipher_key,
            encrypted_data: Vec::new(),
            iv,
            salt,
            mac: Vec::new(),
        };

        // Encripta os dados
        transaction.encrypt_data(secret_key)?;

        // Gera a assinatura da transação
        transaction.sign_transaction(secret_key)?;

        // Verifica se o tamanho da assinatura não excede o máximo permitido
        if transaction.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(TransactionError::InvalidSignature(
                "Assinatura excede o tamanho máximo permitido".to_string(),
            ));
        }

        Ok(transaction)
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> Result<bool, TransactionError> {
        let mac_valid = self.verify_mac()?;
        let data_valid = self.decrypt_data().is_ok();
        let sig_valid = dilithium5::verify_detached_signature(
            &dilithium5::DetachedSignature::from_bytes(signature).map_err(|_| {
                TransactionError::InvalidSignature("Assinatura inválida".to_string())
            })?,
            &self.serialize_data()?,
            public_key,
        )
        .is_ok();

        // Executa todas as verificações mesmo quando falha para prevenir timing attacks
        if mac_valid && data_valid && sig_valid {
            Ok(true)
        } else {
            Err(TransactionError::InvalidSignature(
                "Verificação falhou".to_string(),
            ))
        }
    }

    pub fn size(&self) -> usize {
        self.from.len() + self.to.len() + 8 + 8 + 8 + self.signature.len() + self.public_key.len()
        // +8 para amount, timestamp e nonce
    }

    fn encrypt_data(&mut self, _secret_key: &SecretKey) -> Result<(), TransactionError> {
        let data = self.serialize_data()?;

        // Gera nonce para encriptação
        let nonce = secretbox::Nonce::from_slice(&self.iv)
            .ok_or(TransactionError::InvalidData("Invalid nonce".to_string()))?;

        // Gera chave para encriptação
        let key = secretbox::Key::from_slice(&self.cipher_key)
            .ok_or(TransactionError::InvalidData("Invalid key".to_string()))?;

        // Encripta os dados
        self.encrypted_data = secretbox::seal(&data, &nonce, &key);

        // Gera MAC
        self.generate_mac(&data)?;

        Ok(())
    }

    fn decrypt_data(&self) -> Result<Vec<u8>, TransactionError> {
        let nonce = secretbox::Nonce::from_slice(&self.iv)
            .ok_or(TransactionError::InvalidData("Invalid nonce".to_string()))?;

        let key = secretbox::Key::from_slice(&self.cipher_key)
            .ok_or(TransactionError::InvalidData("Invalid key".to_string()))?;

        secretbox::open(&self.encrypted_data, &nonce, &key)
            .map_err(|_| TransactionError::InvalidData("Decryption failed".to_string()))
    }

    fn verify_mac(&self) -> Result<bool, TransactionError> {
        let key = secretbox::Key::from_slice(&self.cipher_key)
            .ok_or(TransactionError::InvalidData("Invalid key".to_string()))?;

        let nonce = secretbox::Nonce::from_slice(&self.iv)
            .ok_or(TransactionError::InvalidData("Invalid nonce".to_string()))?;

        match secretbox::open(&self.mac, &nonce, &key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn sign_transaction(&mut self, secret_key: &SecretKey) -> Result<(), TransactionError> {
        let data = self.serialize_data()?;
        self.signature = detached_sign(&data, secret_key).as_bytes().to_vec();
        Ok(())
    }

    fn serialize_data(&self) -> Result<Vec<u8>, TransactionError> {
        let data = format!(
            "{}:{}:{}:{}:{}",
            self.from, self.to, self.amount, self.timestamp, self.nonce
        );

        Ok(data.into_bytes())
    }

    fn generate_mac(&mut self, data: &[u8]) -> Result<(), TransactionError> {
        let key = secretbox::Key::from_slice(&self.cipher_key)
            .ok_or(TransactionError::InvalidData("Invalid key".to_string()))?;

        self.mac = secretbox::seal(
            data,
            &secretbox::Nonce::from_slice(&self.iv)
                .ok_or(TransactionError::InvalidData("Invalid nonce".to_string()))?,
            &key,
        );

        Ok(())
    }
}
