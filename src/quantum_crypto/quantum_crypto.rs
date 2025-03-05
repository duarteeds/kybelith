use crate::error::Error;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use oqs::kem::{Algorithm as KemAlgorithm, Kem, PublicKeyRef};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DILITHIUM_SIGNATURE_SIZE: usize = 4627;

#[derive(Debug, Error)]
pub enum OqsError {
    #[error("Erro criptográfico: {0}")]
    CryptoError(String),
    #[error("Algoritmo desabilitado")]
    AlgorithmDisabled,
    #[error("Erro de validação: {0}")]
    ValidationError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Permission {
    Transfer,
    Sign,
    ManageKeys,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionFee {
    amount: u64,
    token: String,
}

pub trait PermissionValidator {
    fn check_permission(&self, permission: &Permission) -> Result<bool, OqsError>;
    fn validate_transaction_fee(&self, fee: &TransactionFee) -> Result<bool, OqsError>;
}

#[derive(Serialize, Deserialize)]
pub struct QuantumCryptoData {
    signature_scheme: String,
    public_key: String,
    signature: String,
    #[serde(default)]
    chaves: HashMap<String, String>,
    #[serde(default)]
    assinaturas: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct QuantumCrypto {
    #[serde(flatten)]
    data: QuantumCryptoData,
    #[serde(skip)]
    kem: Kem,
    #[serde(skip)]
    sig: Sig,
    #[serde(skip)]
    permissions: Vec<Permission>,
    #[serde(skip)]
    transaction_fee: TransactionFee,
    #[serde(skip)]
    nonces_usados: AtomicU64,
    #[serde(skip)]
    ultimo_uso_chave: AtomicU64,
    #[serde(skip)]
    logs_seguros: Mutex<Vec<Vec<u8>>>,
}

impl From<OqsError> for oqs::Error {
    fn from(err: OqsError) -> Self {
        match err {
            OqsError::AlgorithmDisabled => oqs::Error::AlgorithmDisabled,
            OqsError::ValidationError(_) => oqs::Error::AlgorithmDisabled, // mapeamento para erro genérico
            OqsError::CryptoError(_) => oqs::Error::AlgorithmDisabled, // mapeamento para erro genérico
        }
    }
}

impl From<oqs::Error> for OqsError {
    fn from(err: oqs::Error) -> Self {
        match err {
            oqs::Error::AlgorithmDisabled => OqsError::AlgorithmDisabled,
            _ => OqsError::CryptoError("Unknown OQS error".to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for QuantumCrypto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = QuantumCryptoData::deserialize(deserializer)?;

        let kem = Kem::new(KemAlgorithm::Kyber512).map_err(serde::de::Error::custom)?;
        let sig = Sig::new(SigAlgorithm::Dilithium5).map_err(serde::de::Error::custom)?;

        Ok(QuantumCrypto {
            data,
            kem,
            sig,
            permissions: Vec::new(),
            transaction_fee: TransactionFee {
                amount: 0,
                token: String::new(),
            },
            nonces_usados: AtomicU64::new(0),
            ultimo_uso_chave: AtomicU64::new(0),
            logs_seguros: Mutex::new(Vec::new()),
        })
    }
}

impl Debug for QuantumCrypto {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("QuantumCrypto")
            .field("signature_scheme", &self.data.signature_scheme)
            .field("public_key", &self.data.public_key)
            .field("signature", &self.data.signature)
            .finish()
    }
}

// Implementação principal do QuantumCrypto

impl QuantumCrypto {
    pub fn new() -> Result<Self, OqsError> {
        let (public_key, secret_key) = dilithium5::keypair();

        if public_key.as_bytes().is_empty() || secret_key.as_bytes().is_empty() {
            return Err(OqsError::AlgorithmDisabled);
        }

        let kem = Kem::new(KemAlgorithm::Kyber512)?;
        let sig = Sig::new(SigAlgorithm::Dilithium5)?;

        Ok(QuantumCrypto {
            data: QuantumCryptoData {
                signature_scheme: "Dilithium5".to_string(),
                public_key: String::new(),
                signature: String::new(),
                chaves: HashMap::new(),
                assinaturas: HashMap::new(),
            },
            kem,
            sig,
            permissions: Vec::<Permission>::new(),
            transaction_fee: TransactionFee {
                amount: 0,
                token: String::new(),
            },
            nonces_usados: AtomicU64::new(0),
            ultimo_uso_chave: AtomicU64::new(0),
            logs_seguros: Mutex::new(Vec::new()), // Corrigido aqui - envolve Vec::new() em um Mutex
        })
    }

    pub fn register_transaction(&self, transaction_data: &[u8]) -> Result<(), OqsError> {
        // Incrementa o contador de nonces de forma atômica
        let nonce = self.nonces_usados.fetch_add(1, Ordering::SeqCst);

        // Registra nos logs seguros
        let log_entry = self.create_secure_log(transaction_data, nonce)?;
        self.append_to_secure_logs(log_entry);

        Ok(())
    }

    pub fn verify_transaction(
        &self,
        transaction_data: &[u8],
        signature: &[u8],
    ) -> Result<bool, OqsError> {
        self.validar_estado_interno()?;

        let public_key_bytes = STANDARD
            .decode(&self.data.public_key)
            .map_err(|_| OqsError::ValidationError("Chave pública inválida".into()))?;

        let public_key = dilithium5::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| OqsError::AlgorithmDisabled)?;

        let signature = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|_| OqsError::AlgorithmDisabled)?;

        match dilithium5::verify_detached_signature(&signature, transaction_data, &public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn create_secure_log(&self, data: &[u8], nonce: u64) -> Result<Vec<u8>, OqsError> {
        let mut log = Vec::new();
        log.extend_from_slice(&nonce.to_le_bytes());
        log.extend_from_slice(data);

        let signature_bytes = STANDARD
            .decode(&self.data.signature)
            .map_err(|_| OqsError::ValidationError("Assinatura inválida".into()))?;

        let secret_key = dilithium5::SecretKey::from_bytes(&signature_bytes)
            .map_err(|_| OqsError::AlgorithmDisabled)?;

        let signature = dilithium5::detached_sign(&log, &secret_key);
        log.extend_from_slice(signature.as_bytes());

        Ok(log)
    }

    fn append_to_secure_logs(&self, log_entry: Vec<u8>) {
        if let Ok(mut logs) = self.logs_seguros.lock() {
            logs.push(log_entry);
        }
    }

    pub fn verify_signature(&self, data: &[u8]) -> Result<bool, Error> {
        let start = Instant::now();

        // Obtenha a assinatura e chave pública do estado atual
        let signature_bytes = STANDARD
            .decode(self.data.signature.clone())
            .map_err(|_| Error::InvalidSignature)?;
        let public_key_bytes = STANDARD
            .decode(self.data.public_key.clone())
            .map_err(|_| Error::InvalidPublicKey)?;

        // Use a função verify com os dados corretos
        let result = match self.verify(data, &signature_bytes, &public_key_bytes) {
            Ok(_) => true,
            Err(_) => false,
        };

        let elapsed = start.elapsed();

        // Adicionar delay aleatório para mitigar timing attacks
        if elapsed < Duration::from_millis(100) {
            let mut rng = rand::thread_rng();
            thread::sleep(Duration::from_millis(rng.gen_range(0..100)));
        }

        Ok(result)
    }

    fn validar_estado_interno(&self) -> Result<(), OqsError> {
        if self.nonces_usados.load(Ordering::SeqCst) > u64::MAX / 2 {
            return Err(OqsError::AlgorithmDisabled);
        }

        if let Ok(logs) = self.logs_seguros.lock() {
            for log in logs.iter() {
                if log.is_empty() {
                    return Err(OqsError::AlgorithmDisabled);
                }

                let (data, signature) = log.split_at(log.len() - DILITHIUM_SIGNATURE_SIZE);
                self.verify_transaction(data, signature)?;
            }
        }

        Ok(())
    }

    pub fn get_secure_log_count(&self) -> u64 {
        let logs = self.logs_seguros.lock().unwrap();
        logs.len() as u64
    }

    pub fn verify_nonce_sequence(&self) -> Result<bool, OqsError> {
        let current_nonce = self.nonces_usados.load(Ordering::SeqCst);
        let logs = self.logs_seguros.lock().unwrap();

        // Verifica se todos os nonces foram usados sequencialmente
        for (i, log) in logs.iter().enumerate() {
            let nonce_bytes = &log[0..8];
            let nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());
            if nonce != i as u64 {
                return Ok(false);
            }
        }

        Ok(current_nonce == logs.len() as u64)
    }

    pub fn with_keys(
        signature_scheme: String,
        public_key: String,
        signature: String,
    ) -> Result<Self, OqsError> {
        let mut crypto = Self::new()?;

        // Validar o esquema de assinatura
        if signature_scheme != "Dilithium5" {
            return Err(OqsError::ValidationError(
                "Esquema de assinatura inválido".into(),
            ));
        }

        // Validar a chave pública
        if let Err(_) = STANDARD.decode(&public_key) {
            return Err(OqsError::ValidationError("Chave pública inválida".into()));
        }

        // Validar a assinatura
        if let Err(_) = STANDARD.decode(&signature) {
            return Err(OqsError::ValidationError("Assinatura inválida".into()));
        }

        crypto.data.signature_scheme = signature_scheme;
        crypto.data.public_key = public_key;
        crypto.data.signature = signature;

        Ok(crypto)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Secret<Vec<u8>>), OqsError> {
        let (public_key, secret_key) = self.kem.keypair()?;
        let pk_ref = PublicKeyRef::from(&public_key);
        let (ciphertext, shared_secret) = self.kem.encapsulate(&pk_ref)?;

        let encrypted_data: Vec<u8> = data
            .iter()
            .zip(shared_secret.as_ref().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect();

        Ok((
            encrypted_data,
            ciphertext.into_vec(),
            Secret::new(secret_key.into_vec()),
        ))
    }

    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        ciphertext: &[u8],
        secret_key: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, OqsError> {
        let secret_key = self
            .kem
            .secret_key_from_bytes(secret_key.expose_secret())
            .ok_or(OqsError::CryptoError("Chave secreta inválida".into()))?;

        let ciphertext = self
            .kem
            .ciphertext_from_bytes(ciphertext)
            .ok_or(OqsError::CryptoError("Texto cifrado inválido".into()))?;

        let shared_secret = self.kem.decapsulate(&secret_key, &ciphertext)?;

        let decrypted: Vec<u8> = encrypted_data
            .iter()
            .zip(shared_secret.as_ref().iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect();

        Ok(decrypted)
    }

    pub fn sign(&self, data: &[u8], secret_key: &Secret<Vec<u8>>) -> Result<Vec<u8>, OqsError> {
        let secret_key = self
            .sig
            .secret_key_from_bytes(secret_key.expose_secret())
            .ok_or(OqsError::CryptoError("Chave secreta inválida".into()))?;

        let signature = self.sig.sign(data, &secret_key)?;
        Ok(signature.into_vec())
    }

    pub fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), OqsError> {
        let public_key = self
            .sig
            .public_key_from_bytes(public_key)
            .ok_or(OqsError::CryptoError("Chave pública inválida".into()))?;

        let signature = self
            .sig
            .signature_from_bytes(signature)
            .ok_or(OqsError::CryptoError("Assinatura inválida".into()))?;

        self.sig
            .verify(data, &signature, &public_key)
            .map_err(|e| OqsError::CryptoError(e.to_string()))
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), OqsError> {
        let (public_key, secret_key) = self.sig.keypair()?;
        Ok((public_key.into_vec(), secret_key.into_vec()))
    }

    pub fn set_permissions(&mut self, permissions: Vec<Permission>) -> Result<(), OqsError> {
        self.permissions = permissions;
        Ok(())
    }

    pub fn set_transaction_fee(&mut self, fee: TransactionFee) -> Result<(), OqsError> {
        self.transaction_fee = fee;
        Ok(())
    }

    pub fn verify_permission(&self, permission: &Permission) -> Result<bool, OqsError> {
        self.check_permission(permission)
    }

    pub fn clear_sensitive_data(&mut self) {
        self.data.public_key.clear();
        self.data.signature.clear();
    }

    pub fn verify_str(
        &self,
        data: &[u8],
        signature: &str,
        public_key: &str,
    ) -> Result<(), OqsError> {
        let signature_bytes = STANDARD
            .decode(signature)
            .map_err(|_| OqsError::ValidationError("Assinatura inválida".into()))?;
        let public_key_bytes = STANDARD
            .decode(public_key)
            .map_err(|_| OqsError::ValidationError("Chave pública inválida".into()))?;

        self.verify(data, &signature_bytes, &public_key_bytes)
    }

    pub fn rotacionar_chaves(&mut self, nova_chave: Vec<u8>) -> Result<(), OqsError> {
        if nova_chave.len() < 64 {
            return Err(OqsError::ValidationError(
                "Tamanho de chave inválido".into(),
            ));
        }

        let meio = nova_chave.len() / 2;

        // Usar _ para indicar que a variável é intencionalmente não utilizada
        let _public_key = self
            .kem
            .public_key_from_bytes(&nova_chave[..meio])
            .ok_or(OqsError::CryptoError("Chave pública inválida".into()))?;

        self.ultimo_uso_chave.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::SeqCst,
        );

        self.clear_sensitive_data();
        Ok(())
    }

    // Métodos de acesso
    pub fn signature_scheme(&self) -> &str {
        &self.data.signature_scheme
    }

    pub fn public_key(&self) -> &str {
        &self.data.public_key
    }

    pub fn signature(&self) -> &str {
        &self.data.signature
    }
}

impl PermissionValidator for QuantumCrypto {
    fn check_permission(&self, permission: &Permission) -> Result<bool, OqsError> {
        Ok(self.permissions.contains(permission))
    }

    fn validate_transaction_fee(&self, fee: &TransactionFee) -> Result<bool, OqsError> {
        if fee.token.is_empty() || fee.token != "QST" {
            return Err(OqsError::ValidationError("Token inválido".into()));
        }

        if fee.amount == 0 {
            return Err(OqsError::ValidationError("Taxa zero não permitida".into()));
        }

        Ok(fee.amount >= self.transaction_fee.amount && fee.token == self.transaction_fee.token)
    }
}

//Proteção Contra Ataques de Tempo:
//Verificação de Integridade:
//Proteção Contra Replay Attacks:
//Gerenciamento de Ciclo de Vida das Chaves:
//Proteção Contra Side-Channel Attacks:
//Auditoria e Logs Seguros:
//Validação de Entrada:
//Criptografia de Dados em Repouso:
