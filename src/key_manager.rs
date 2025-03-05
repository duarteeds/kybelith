use crate::error::TransactionError;
use anyhow::{Context, Result};
use oqs::kem::PublicKeyRef;
use oqs::kem::{Algorithm as KemAlgorithm, Kem};
use oqs::sig::{Algorithm as SigAlgorithm, Sig};
use rusqlite::params;
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct SerializableCiphertext {
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializableSharedSecret {
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializableBackup {
    ciphertext: SerializableCiphertext,
    shared_secret: SerializableSharedSecret,
}

pub struct KeyManager {
    kem: Kem,
    sig: Sig,
}

impl KeyManager {
    pub fn new() -> Result<Self> {
        let kem = Kem::new(KemAlgorithm::Kyber512).context("Falha ao inicializar Kyber512")?;
        let sig = Sig::new(SigAlgorithm::Dilithium5) // Atualizado para Dilithium5
            .context("Falha ao inicializar Dilithium5")?;

        Ok(Self { kem, sig })
    }

    pub fn delete_transaction_params(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), TransactionError> {
        if from.is_empty() || to.is_empty() {
            return Err(TransactionError::InvalidParameter(
                "Endereço inválido".to_string(),
            ));
        }
        if amount == 0 {
            return Err(TransactionError::InvalidParameter(
                "Quantidade inválida".to_string(),
            ));
        }
        Ok(())
    }

    pub fn delay_operation(&self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let delay = rng.gen_range(10..100); // Atraso aleatório entre 10ms e 100ms
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }

    pub fn rotate_keys(&mut self, conn: &mut Connection) -> Result<()> {
        let (new_public_key, _new_secret_key) = self.generate_quantum_keys()?;

        conn.execute(
            "UPDATE active_keys SET is_active = 0 WHERE is_active = 1",
            [],
        )?;

        conn.execute(
            "INSERT INTO active_keys (public_key, created_at, is_active) VALUES (?1, ?2, 1)",
            params![
                new_public_key,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            ],
        )?;

        Ok(())
    }

    pub fn backup_keys(&self, backup_path: &str) -> Result<()> {
        // Primeiro, obtenha um par de chaves
        let (public_key, _) = self.kem.keypair()?;
        let public_key_ref = PublicKeyRef::from(&public_key);

        // Encapsule para obter ciphertext e shared_secret
        let (ciphertext, shared_secret) = self.kem.encapsulate(&public_key_ref)?;

        // Crie o backup serializável
        let serializable_backup = SerializableBackup {
            ciphertext: SerializableCiphertext {
                data: ciphertext.into_vec(),
            },
            shared_secret: SerializableSharedSecret {
                data: shared_secret.as_ref().to_vec(),
            },
        };

        // Serialize para string e salve no arquivo
        let json_string = serde_json::to_string(&serializable_backup)?;
        std::fs::write(backup_path, json_string)?;

        Ok(())
    }

    pub fn validate_transaction_params(&self, from: &str, to: &str, amount: u64) -> Result<()> {
        if from.len() < 32 || to.len() < 32 {
            return Err(anyhow::anyhow!("Endereços inválidos"));
        }

        if amount == 0 {
            return Err(anyhow::anyhow!("Quantidade inválida"));
        }

        Ok(())
    }

    pub fn log_key_operation(&self, conn: &mut Connection, operation: &str) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        conn.execute(
            "INSERT INTO key_operations (operation, timestamp) VALUES (?1, ?2)",
            params![operation, timestamp],
        )?;

        Ok(())
    }

    pub fn generate_quantum_keys(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (public_key, secret_key) = self
            .kem
            .keypair()
            .context("Falha ao gerar par de chaves Kyber")?;

        Ok((public_key.into_vec(), secret_key.into_vec()))
    }

    pub fn generate_signing_keys(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (public_key, secret_key) = self
            .sig
            .keypair()
            .context("Falha ao gerar par de chaves Dilithium")?;

        Ok((public_key.into_vec(), secret_key.into_vec()))
    }

    pub fn create_secure_transaction<'a>(
        &self,
        from: String,
        to: String,
        amount: u64,
        conn: &'a mut Connection,
    ) -> Result<rusqlite::Transaction<'a>> {
        let (pub_key, secret_key_bytes) = self.generate_signing_keys()?;

        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let message = format!("{}:{}:{}:{}", from, to, amount, timestamp);

        let signature = self.sig.sign(
            message.as_bytes(),
            &self
                .sig
                .secret_key_from_bytes(&secret_key_bytes)
                .ok_or_else(|| anyhow::anyhow!("Falha ao criar chave secreta"))?,
        )?;

        transaction.execute(
            "INSERT INTO transactions (from_address, to_address, amount, timestamp, signature, public_key) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                from,
                to,
                amount,
                timestamp,
                signature.as_ref(),
                pub_key
            ],
        )?;

        Ok(transaction)
    }
}
