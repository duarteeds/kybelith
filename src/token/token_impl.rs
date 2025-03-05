use crate::quantum_crypto::quantum_crypto::Permission;
use crate::quantum_crypto::OqsError;
use crate::quantum_crypto::QuantumCrypto;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub id: u64,
    pub name: String,
    pub symbol: String,
    pub total_supply: u64,
    pub balances: HashMap<String, u64>,
    pub creator: String,
    pub quantum_crypto: QuantumCrypto,
}

impl Token {
    pub fn new(
        name: String,
        symbol: String,
        total_supply: u64,
        creator: String,
    ) -> Result<Self, OqsError> {
        let mut balances = HashMap::new();
        balances.insert(creator.clone(), total_supply);

        // Criar instância do QuantumCrypto
        let crypto = QuantumCrypto::new()?;

        // Gerar par de chaves
        let (public_key, secret_key) = crypto.generate_keypair()?;

        // Criar e assinar dados do token
        let data = format!("{}{}{}", name, symbol, total_supply).into_bytes();
        let signature = crypto.sign(&data, &Secret::new(secret_key))?;

        // Converter para base64
        let public_key_str = STANDARD.encode(&public_key);
        let signature_str = STANDARD.encode(&signature);

        // Criar token com QuantumCrypto usando Dilithium5
        Ok(Token {
            id: 0,
            name,
            symbol,
            total_supply,
            balances,
            creator,
            quantum_crypto: QuantumCrypto::with_keys(
                "Dilithium5".to_string(), // Corrigido para Dilithium5
                public_key_str,
                signature_str,
            )?,
        })
    }

    pub fn balance_of(&self, address: &String) -> u64 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    pub fn transfer(&mut self, to: &str, amount: u64) -> Result<(), crate::error::Error> {
        if amount == 0 {
            return Err(crate::error::Error::InvalidAmount);
        }

        let current_balance = self.balances.get(&self.creator).copied().unwrap_or(0);
        let new_balance = current_balance
            .checked_sub(amount)
            .ok_or(crate::error::Error::InvalidAmount)?;

        let recipient_balance = self
            .balances
            .get(to)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(crate::error::Error::InvalidAmount)?;

        self.balances.insert(self.creator.clone(), new_balance);
        self.balances.insert(to.to_string(), recipient_balance);

        Ok(())
    }

    pub fn mint(&mut self, address: String, amount: u64) -> Result<(), String> {
        // Validar a quantidade
        if amount == 0 {
            return Err("Quantidade de mint deve ser maior que zero".to_string());
        }

        // Validar usando QuantumCrypto antes de mint
        if let Err(_) = self
            .quantum_crypto
            .verify_permission(&Permission::ManageKeys)
        {
            return Err("Permissão negada para mint".to_string());
        }

        *self.balances.entry(address).or_insert(0) += amount;
        self.total_supply += amount;
        Ok(())
    }

    pub fn save_to_file(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(self)?;
        let mut file = File::create(filename)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn load_from_file(filename: &str) -> Result<Self, Box<dyn Error>> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let token: Token = serde_json::from_str(&contents)?;
        Ok(token)
    }

    // Método para verificar a validade do token
    pub fn verify(&self) -> Result<bool, OqsError> {
        let data = format!("{}{}{}", self.name, self.symbol, self.total_supply).into_bytes();
        let signature = STANDARD
            .decode(self.quantum_crypto.signature())
            .map_err(|_| OqsError::ValidationError("Invalid signature format".to_string()))?;
        let public_key = STANDARD
            .decode(self.quantum_crypto.public_key())
            .map_err(|_| OqsError::ValidationError("Invalid public key format".to_string()))?;

        self.quantum_crypto
            .verify(&data, &signature, &public_key)
            .map(|_| true)
    }
}
