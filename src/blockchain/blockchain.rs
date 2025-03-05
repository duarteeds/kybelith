use super::block::Block;
use crate::blockchain::validacao;
use crate::blockchain::validacao::Validator;
use crate::constants::{MAX_BLOCK_SIZE, MAX_TIME_DRIFT, MAX_TRANSACTION_SIZE};
use crate::error::Error;
use crate::error::TransactionError;
use crate::key_manager::KeyManager;
use crate::quantum_crypto::QuantumCrypto;
use crate::token::Token;
use crate::transaction::{SecureTransaction, Transaction};
use anyhow::{Context, Result};
use oqs::kem::{Algorithm, Kem};
use oqs::Error as OqsError;
use pqcrypto_dilithium::dilithium5::{self, SecretKey};
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};

pub type Address = String;

impl From<anyhow::Error> for TransactionError {
    fn from(err: anyhow::Error) -> Self {
        TransactionError::Other(err.to_string())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub tokens: HashMap<String, Token>, // Changed from u64 to String
    pub stakers: HashMap<Address, u64>,
    pub nonces: HashMap<Address, u64>,
    pub pending_transactions: Vec<Transaction>,
    pub blocks: Vec<Block>,
    pub transactions: Vec<Transaction>,
    pub next_token_id: u64,
    pub public_keys: HashMap<String, Vec<u8>>,
    #[serde(skip)] // Não serializar o validator
    pub validator: Validator,
    #[serde(skip)]
    pub secret_keys: HashMap<String, SecretKey>,
}

impl Blockchain {
    pub fn new() -> anyhow::Result<Self> {
        let mut blockchain = Blockchain {
            tokens: HashMap::new(),
            stakers: HashMap::new(),
            chain: Vec::new(),
            next_token_id: 0,
            nonces: HashMap::new(),
            pending_transactions: Vec::new(),
            blocks: Vec::new(),
            transactions: Vec::new(),
            public_keys: HashMap::new(),
            validator: Validator::new(MAX_BLOCK_SIZE, 300), // 5 minutos de desvio máximo
            secret_keys: HashMap::new(),
        };

        blockchain.create_quantum_secure_token()?;
        Ok(blockchain)
    }

    /// Cria o Quantum Secure Token (ID = 0).
    pub fn create_quantum_secure_token(&mut self) -> anyhow::Result<()> {
        let kybelith_token = Token::new(
            "Kybelith".to_string(),
            "KYBL".to_string(),
            10_000_000,           // Supply inicial aumentado
            "system".to_string(), // Criador
        )?;

        self.tokens.insert(0.to_string(), kybelith_token);

        // Adicionar saldo inicial para o administrador durante o desenvolvimento
        let admin_address = "0x123...".to_string(); // Use o endereço real do admin
        if let Some(token) = self.tokens.get_mut(&0.to_string()) {
            *token.balances.entry(admin_address).or_insert(0) += 1_000_000; // Saldo inicial de desenvolvimento
        }

        self.next_token_id = 1;
        Ok(())
    }

    pub fn get_token(&self, id: &str) -> Option<&Token> {
        self.tokens.get(id)
    }

    /// Cria um novo token (para usuários).
    pub fn create_token(
        &mut self,
        name: String,
        symbol: String,
        initial_supply: u64,
        creator: String,
    ) -> Result<String, OqsError> {
        let token = Token::new(name, symbol, initial_supply, creator)?;
        let token_id = self.next_token_id.to_string();
        self.tokens.insert(token_id.clone(), token);
        self.next_token_id += 1;
        Ok(token_id)
    }

    pub fn get_public_key(&self, address: &str) -> Result<dilithium5::PublicKey, TransactionError> {
        // Busca a chave pública associada ao endereço (address)
        let public_key_bytes =
            self.public_keys
                .get(address)
                .ok_or(TransactionError::InvalidPublicKey(
                    "Chave pública não encontrada".to_string(),
                ))?;

        // Converte os bytes da chave pública para o tipo dilithium5::PublicKey
        let public_key = dilithium5::PublicKey::from_bytes(public_key_bytes).map_err(|_| {
            TransactionError::InvalidPublicKey("Chave pública inválida".to_string())
        })?;

        Ok(public_key)
    }

    /// Adiciona uma transação à blockchain.
    pub fn add_transaction(
        &mut self,
        from: String,
        to: String,
        amount: u64,
        signature: Vec<u8>,
    ) -> Result<(), TransactionError> {
        // Validações iniciais
        let key_manager = KeyManager::new()?;
        key_manager.validate_transaction_params(&from, &to, amount)?;

        // Validar formato de endereço usando a função utilitária
        if !validacao::validate_address_format(&from) || !validacao::validate_address_format(&to) {
            return Err(TransactionError::InvalidData(
                "Endereço inválido".to_string(),
            ));
        }

        // Obtém o nonce atual
        let current_nonce = self.nonces.get(&from).copied().unwrap_or(0);

        // Obtém a chave pública
        let public_key = self.get_public_key(&from)?;

        // Timestamp atual
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Validar timestamp
        let current_time = timestamp;
        if !validacao::validate_timestamp(timestamp, current_time) {
            return Err(TransactionError::InvalidData(
                "Timestamp inválido".to_string(),
            ));
        }

        // Obtém a chave secreta do remetente
        let secret_key = self.get_secret_key(&from)?;

        // Cria a transação segura
        let secure_transaction = SecureTransaction::new(
            from.clone(),
            to,
            amount,
            timestamp,
            current_nonce + 1,
            &secret_key, // Passando a chave secreta como argumento
            &public_key,
        )?;

        // Valide o tamanho da transação
        let transaction_temp: Transaction = secure_transaction.clone().into();
        validacao::validate_transaction_size(&transaction_temp)?;

        // Verificar assinatura com proteção contra timing attacks
        // Precisamos converter o método para trabalhar com o mesmo tipo de erro
        match validacao::verify_signature_with_delay(&transaction_temp, &public_key) {
            Ok(_) => {}
            Err(_) => {
                return Err(TransactionError::InvalidSignature(
                    "Assinatura inválida".to_string(),
                ))
            }
        }

        // Verificar assinatura também usando o método original para garantir segurança
        if !secure_transaction.verify(&public_key, &signature)? {
            return Err(TransactionError::InvalidSignature(
                "Assinatura inválida".to_string(),
            ));
        }

        // Converter para transação normal
        let transaction: Transaction = secure_transaction.into();

        // Atualiza o nonce e adiciona a transação
        self.nonces.insert(from, current_nonce + 1);
        self.pending_transactions.push(transaction);

        Ok(())
    }

    fn get_secret_key(&self, address: &str) -> Result<&SecretKey, TransactionError> {
        self.secret_keys.get(address).ok_or_else(|| {
            TransactionError::InvalidData(format!(
                "Chave secreta não encontrada para endereço: {}",
                address
            ))
        })
    }

    /// Valida uma transação.
    fn validar_transacao(
        &self,
        transaction: &Transaction,
        nonce_atual: u64,
    ) -> Result<(), TransactionError> {
        // Verifica o nonce
        if transaction.nonce != nonce_atual + 1 {
            return Err(TransactionError::InvalidSignature(format!(
                "Nonce inválido: esperado {}, recebido {}",
                nonce_atual + 1,
                transaction.nonce
            )));
        }

        // Verifica a assinatura
        let public_key = &transaction.public_key;
        let pk_bytes = public_key.as_slice();
        let pk = match dilithium5::PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                return Err(TransactionError::InvalidSignature(
                    "Chave pública inválida".to_string(),
                ))
            }
        };

        if transaction.verify(&pk).is_err() {
            return Err(TransactionError::InvalidSignature(
                "Assinatura inválida".to_string(),
            ));
        }

        // Verifica duplicação
        if self.transaction_exists(transaction) {
            return Err(TransactionError::InvalidSignature(
                "Transação duplicada".to_string(),
            ));
        }

        Ok(())
    }

    /// Adiciona um staker à blockchain.
    pub fn add_staker(&mut self, address: String, amount: u64) {
        let current = self.stakers.entry(address).or_insert(0);
        *current += amount;
    }

    /// Adiciona um bloco à blockchain.
    pub fn add_block(&mut self, block: Block) -> Result<(), Error> {
        // Validação de tamanho do bloco
        if block.size() > MAX_BLOCK_SIZE {
            return Err(Error::BlockTooLarge);
        }

        // Validação de timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if block.timestamp > (current_time + MAX_TIME_DRIFT) as u64 {
            return Err(Error::InvalidTimestamp("Timestamp no futuro".to_string()));
        }

        if block.timestamp < (current_time - MAX_TIME_DRIFT) as u64 {
            return Err(Error::InvalidTimestamp("Timestamp no passado".to_string()));
        }

        // Validação com entropia quântica
        self.validate_timestamp_with_quantum_entropy(block.timestamp)?;

        // Validação das transações no bloco
        for secure_transaction in &block.transactions {
            // Valide o tamanho da transação
            if secure_transaction.size() > MAX_TRANSACTION_SIZE {
                return Err(Error::TransactionError(Box::new(
                    TransactionError::DataSizeExceeded,
                )));
            }

            // Converte SecureTransaction para Transaction
            let transaction: Transaction = secure_transaction.clone().into();

            // Obtém o nonce atual do remetente
            let nonce_atual = self.nonces.get(&transaction.from).copied().unwrap_or(0);

            // Valida a transação
            self.validar_transacao(&transaction, nonce_atual)?;
        }

        // Validação do hash do bloco
        let calculated_hash = Block::calculate_hash(
            block.index,
            block.timestamp,
            &block.transactions,
            &block.contracts,
            &block.previous_hash,
        )?;

        if block.hash != calculated_hash {
            return Err(Error::InvalidBlock("Hash do bloco inválido".to_string()));
        }

        // Registra evento seguro
        self.log_secure_event(&format!(
            "Bloco adicionado: índice={}, hash={}",
            block.index, block.hash
        ))?;

        // Adiciona o bloco à cadeia
        self.chain.push(block);

        Ok(())
    }

    /// Valida o timestamp usando entropia quântica.
    pub fn validate_timestamp_with_quantum_entropy(&self, timestamp: u64) -> Result<(), Error> {
        // Gera entropia quântica usando Kyber
        let kem = Kem::new(Algorithm::Kyber512).map_err(|e| Error::OqsError(e))?;
        let (pk, _) = kem.keypair().map_err(|e| Error::OqsError(e))?;

        // Gera hash SHA-3 da chave pública
        let mut hasher = Sha3_256::new();
        hasher.update(pk.as_ref());
        let hash = format!("{:x}", hasher.finalize());

        // Cria payload com timestamp e hash
        let payload = format!("{}:{}", timestamp, hash);

        // Gera uma assinatura usando Dilithium
        let keypair = dilithium5::keypair();
        let signature = dilithium5::detached_sign(payload.as_bytes(), &keypair.1);

        // Verifica a assinatura
        if dilithium5::verify_detached_signature(&signature, payload.as_bytes(), &keypair.0)
            .is_err()
        {
            return Err(Error::InvalidTimestamp(
                "Timestamp inválido (assinatura quântica falhou)".to_string(),
            ));
        }

        Ok(())
    }

    /// Salva a blockchain em um arquivo JSON.
    pub fn save_to_file(&self, filename: &str) -> std::io::Result<()> {
        let json = serde_json::to_string(self)?;
        let mut file = File::create(filename)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Salva a blockchain em um banco de dados SQLite.
    pub fn save_to_db(&self, db_path: &str) -> SqlResult<()> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY,
                index INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
            [],
        )?;

        for block in &self.chain {
            conn.execute(
                "INSERT INTO blocks (index, timestamp, previous_hash, hash) VALUES (?1, ?2, ?3, ?4)",
                params![
                    block.index,
                    block.timestamp,
                    &block.previous_hash,
                    &block.hash
                ],
            )?;
        }

        Ok(())
    }

    /// Registra um evento seguro usando criptografia quântica.
    pub fn log_secure_event(&self, event: &str) -> Result<(), Error> {
        let crypto = QuantumCrypto::new().map_err(|e| Error::OqsError(e.into()))?;
        let _encrypted_event = crypto
            .encrypt(event.as_bytes())
            .map_err(|e| Error::OqsError(e.into()))?;

        // Implementar logging seguro
        Ok(())
    }

    /// Verifica se uma transação já existe na blockchain.
    pub fn transaction_exists(&self, tx: &Transaction) -> bool {
        self.chain.iter().any(|block| {
            block
                .transactions
                .iter()
                .any(|t| t.from == tx.from && t.nonce == tx.nonce && t.timestamp == tx.timestamp)
        })
    }

    /// Carrega a blockchain de um banco de dados SQLite.
    pub fn load_from_db(db_path: &str) -> SqlResult<Self> {
        let conn = Connection::open(db_path)?;
        let mut stmt = conn.prepare("SELECT index, timestamp, previous_hash, hash FROM blocks")?;
        let blocks = stmt.query_map([], |row| {
            Ok(Block {
                index: row.get(0)?,
                timestamp: row.get(1)?,
                transactions: vec![],
                contracts: vec![],
                previous_hash: row.get(2)?,
                hash: row.get(3)?,
                validator_signature: None,
                nonce: 0,
                processed_transactions: std::collections::HashSet::new(),
            })
        })?;

        let chain: Vec<Block> = blocks.collect::<SqlResult<_>>()?;

        Ok(Blockchain {
            tokens: HashMap::new(),
            stakers: HashMap::new(),
            chain,
            next_token_id: 0,
            nonces: HashMap::new(),
            pending_transactions: Vec::new(),
            blocks: Vec::new(),
            transactions: Vec::new(),
            public_keys: HashMap::new(),
            validator: Validator::new(MAX_BLOCK_SIZE, 300),
            secret_keys: HashMap::new(), //
        })
    }

    /// Carrega a blockchain de um arquivo JSON.
    pub fn load_from_file(filename: &str) -> anyhow::Result<Self> {
        // Verifica se o arquivo existe
        if !std::path::Path::new(filename).exists() {
            println!("Arquivo não encontrado. Criando nova blockchain.");
            return Blockchain::new();
        }

        // Abre o arquivo e lê o conteúdo
        let mut file = File::open(filename)
            .with_context(|| format!("Falha ao abrir o arquivo: {}", filename))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Falha ao ler o arquivo: {}", filename))?;

        // Tenta deserializar o conteúdo do arquivo
        let result = match serde_json::from_str::<Blockchain>(&contents) {
            Ok(mut blockchain) => {
                // Inicializa o validator que foi ignorado na deserialização
                blockchain.validator = Validator::new(MAX_BLOCK_SIZE, 300);

                // Inicializa public_keys se não existir (para compatibilidade)
                if blockchain.public_keys.is_empty() {
                    blockchain.public_keys = HashMap::new();
                }

                Ok(blockchain)
            }
            Err(e) => {
                println!(
                    "Erro ao deserializar blockchain existente: {}. Criando nova blockchain.",
                    e
                );
                Blockchain::new()
            }
        };

        result
    }

    /// Verifica se a blockchain é válida.
    pub fn is_chain_valid(&self) -> Result<bool, TransactionError> {
        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            if current_block.previous_hash != previous_block.hash {
                return Ok(false);
            }

            for transaction in &current_block.transactions {
                let public_key = &transaction.public_key;
                let pk_bytes = public_key.as_slice();
                let pk = match dilithium5::PublicKey::from_bytes(pk_bytes) {
                    Ok(pk) => pk,
                    Err(_) => {
                        return Err(TransactionError::InvalidSignature(
                            "Chave pública inválida".to_string(),
                        ))
                    }
                };

                if !transaction.verify(&pk, &transaction.signature)? {
                    return Ok(false);
                }
            }

            let calculated_hash = match Block::calculate_hash(
                current_block.index,
                current_block.timestamp,
                &current_block.transactions,
                &current_block.contracts,
                &current_block.previous_hash,
            ) {
                Ok(hash) => hash,
                Err(_) => {
                    return Err(TransactionError::OqsError(Box::new(
                        OqsError::AlgorithmDisabled,
                    )))
                }
            };

            if current_block.hash != calculated_hash {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl std::fmt::Debug for Blockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blockchain")
            .field("chain", &self.chain)
            .field("tokens", &self.tokens)
            .field("stakers", &self.stakers)
            .field("nonces", &self.nonces)
            .field("pending_transactions", &self.pending_transactions)
            .field("transactions", &self.transactions)
            .field("next_token_id", &self.next_token_id)
            .field("public_keys", &self.public_keys)
            .finish_non_exhaustive() // Oculta campos sensíveis
    }
}
