use crate::error::Error;
use crate::transaction::Transaction;
use anyhow::Result;
use pqcrypto_dilithium::dilithium5::{self, detached_sign, verify_detached_signature};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomToken {
    pub id: u32,
    pub name: String,
    pub symbol: String,
    pub supply: u64,
    pub owner: String,
    pub signature: Vec<u8>,
    #[serde(skip)]
    public_key: Option<Vec<u8>>,
    #[serde(skip)]
    secret_key: Option<Vec<u8>>,
    processed_transactions: std::collections::HashSet<String>,
}

impl CustomToken {
    pub fn new(id: u32, name: String, symbol: String, supply: u64, owner: String) -> Result<Self> {
        if id == 0 {
            return Err(anyhow::anyhow!("ID inválido"));
        }

        // Gerar chaves pública e secreta
        let (public_key, secret_key) = Self::generate_keys()?;

        Ok(Self {
            id,
            name,
            symbol,
            supply,
            owner,
            signature: Vec::new(),
            public_key: Some(public_key),
            secret_key: Some(secret_key),
            processed_transactions: std::collections::HashSet::new(),
        })
    }

    fn generate_keys() -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = dilithium5::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    pub fn sign_transaction(&mut self, data: &str) -> Result<()> {
        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Chave secreta não disponível"))?;

        let sk = SecretKey::from_bytes(secret_key)
            .map_err(|e| anyhow::anyhow!("Falha ao processar chave secreta: {}", e))?;

        let signature = detached_sign(data.as_bytes(), &sk);
        self.signature = signature.as_bytes().to_vec();

        Ok(())
    }

    pub fn transfer(&mut self, _: String, amount: u64) -> Result<()> {
        if amount == 0 {
            return Err(anyhow::anyhow!("Quantidade deve ser maior que zero"));
        }
        if self.supply < amount {
            return Err(anyhow::anyhow!("Saldo insuficiente"));
        }

        self.supply -= amount;
        Ok(())
    }

    pub fn verify_signature(&self, data: &str) -> Result<bool> {
    if self.signature.is_empty() {
        return Err(anyhow::anyhow!("Assinatura não presente"));
    }

    let public_key = self
        .public_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Chave pública não disponível"))?;

    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| anyhow::anyhow!("Falha ao processar chave pública: {}", e))?;

    let signature = DetachedSignature::from_bytes(&self.signature)
        .map_err(|e| anyhow::anyhow!("Falha ao processar assinatura: {}", e))?;

    Ok(verify_detached_signature(&signature, data.as_bytes(), &pk).is_ok())
}

    pub fn process_transfer(&mut self, tx: &Transaction) -> Result<(), Error> {
        if self.processed_transactions.contains(&tx.hash) {
            return Err(Error::DoubleSpending);
        }

        self.transfer(tx.from.clone(), tx.amount)?;
        Ok(())
    }

    pub fn export_public_key(&self) -> Result<Vec<u8>> {
        self.public_key
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Chave pública não disponível"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error; // Mova a importação para dentro do módulo de testes

    #[test]
    fn test_token_creation() -> Result<(), Box<dyn Error>> {
        let token = CustomToken::new(
            1,
            "MeuToken".to_string(),
            "MTK".to_string(),
            1000,
            "Endereço1".to_string(),
        )?;

        assert_eq!(token.name, "MeuToken");
        assert_eq!(token.supply, 1000);
        assert_eq!(token.owner, "Endereço1");
        Ok(())
    }

    #[test]
    fn test_token_transfer() -> Result<(), Box<dyn Error>> {
        let mut token = CustomToken::new(
            1,
            "MeuToken".to_string(),
            "MTK".to_string(),
            1000,
            "Endereço1".to_string(),
        )?;

        assert!(token.transfer("Endereço2".to_string(), 100).is_ok());
        assert_eq!(token.supply, 900);
        Ok(())
    }

    #[test]
    fn test_token_transfer_insufficient_supply() -> Result<(), Box<dyn Error>> {
        let mut token = CustomToken::new(
            1,
            "MeuToken".to_string(),
            "MTK".to_string(),
            50, // Saldo inicial menor que 100
            "Endereço1".to_string(),
        )?;

        assert!(token.transfer("Endereço2".to_string(), 100).is_err());
        Ok(())
    }

    #[test]
    fn test_token_sign_and_verify() -> Result<(), Box<dyn Error>> {
        let mut token = CustomToken::new(
            1,
            "MeuToken".to_string(),
            "MTK".to_string(),
            1000,
            "Endereço1".to_string(),
        )?;

        let transaction_data = "Transferir 100 MTK para Endereço2";
        token.sign_transaction(transaction_data)?;
        assert!(!token.signature.is_empty());
        assert!(token.verify_signature(transaction_data)?);
        Ok(())
    }
}
