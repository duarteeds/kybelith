use crate::constants::TOKEN_CREATION_BASE_FEE_2CHAR;
use crate::constants::TOKEN_CREATION_BASE_FEE_3CHAR;
use crate::constants::TOKEN_CREATION_BASE_FEE_4CHAR;
use crate::constants::TOKEN_CREATION_BASE_FEE_DEFAULT;
use crate::constants::{
    BURN_PERCENTAGE, DEV_FUND_ADDRESS, DEV_PERCENTAGE, LIQUIDITY_FUND_ADDRESS, STAKING_PERCENTAGE,
    STAKING_POOL_ADDRESS, TRANSFER_FEE_DIVISOR, TRANSFER_FEE_MINIMUM,
};
use crate::transaction::secure_transaction::SecureTransaction;
use anyhow::{Context, Result};
use log::info;
use pqcrypto_dilithium::dilithium5;
use rusqlite::params;
use std::path::Path;

use crate::blockchain::Blockchain;
use crate::database::Database;
use crate::key_manager::KeyManager;
use crate::token::custom_token::CustomToken;
use crate::token::token_builder::TokenBuilder;
use crate::token::Token;

pub struct QuantumBlockchainApp {
    pub blockchain: Blockchain,
    pub key_manager: KeyManager,
    pub database: Database,
}

impl QuantumBlockchainApp {
    pub fn new() -> Result<Self> {
        let key_manager =
            KeyManager::new().context("Falha ao inicializar gerenciador de chaves")?;

        let blockchain = if Path::new(crate::BLOCKCHAIN_FILE).exists() {
            let mut blockchain = Blockchain::load_from_file(crate::BLOCKCHAIN_FILE)
                .context("Falha ao carregar blockchain")?;

            // Verifica se o Quantum Secure Token está presente
            if !blockchain.tokens.contains_key(&0.to_string()) {
                blockchain.create_quantum_secure_token()?;
                blockchain.save_to_file(crate::BLOCKCHAIN_FILE)?;
            }

            blockchain
        } else {
            info!("Criando nova blockchain");
            let blockchain = Blockchain::new().context("Falha ao criar nova blockchain")?;
            blockchain.save_to_file(crate::BLOCKCHAIN_FILE)?;
            blockchain
        };

        let database =
            Database::new(crate::DB_PATH).context("Falha ao inicializar banco de dados")?;

        Ok(Self {
            blockchain,
            key_manager,
            database,
        })
    }

    pub fn create_token(&mut self, name: String, symbol: String, supply: u64) -> Result<Token> {
        let token = TokenBuilder::new()
            .name(name.clone())
            .symbol(symbol.clone())
            .total_supply(supply)
            .creator("admin".to_string())
            .build()
            .context("Falha ao construir token")?;

        let conn = self
            .database
            .get_connection_mut()
            .context("Falha ao obter conexão com banco de dados")?;

        // Insere o token no banco de dados (sem passar o ID)
        conn.execute(
            "INSERT INTO tokens (name, symbol, supply, creator) VALUES (?1, ?2, ?3, ?4)",
            params![token.name, token.symbol, token.total_supply, token.creator],
        )
        .context("Falha ao inserir token no banco de dados")?;

        Ok(token)
    }

    pub fn create_custom_token(
        &mut self,
        id: u32,
        name: String,
        symbol: String,
        supply: u64,
        owner: String,
    ) -> Result<CustomToken> {
        // Validação de ID
        if id == 0 {
            return Err(anyhow::anyhow!("ID 0 é reservado para o token nativo KYBL").into());
        }

        // Validação de nome
        if name.trim().is_empty() || name.len() > 64 {
            return Err(anyhow::anyhow!("Nome do token deve ter entre 1 e 64 caracteres").into());
        }

        // Validação de símbolo
        if !symbol.chars().all(|c| c.is_ascii_uppercase()) || symbol.len() < 2 || symbol.len() > 10
        {
            return Err(anyhow::anyhow!(
                "Símbolo do token deve ter entre 2 e 10 caracteres maiúsculos"
            )
            .into());
        }

        // Validação de supply
        if supply == 0 || supply > u64::MAX / 2 {
            return Err(anyhow::anyhow!("Supply deve estar entre 1 e 2^63-1").into());
        }

        // Calcular a taxa de criação do token
        let token_creation_fee = self.calculate_token_creation_fee(
            symbol.len(),
            supply,
            self.get_creator_reputation(&owner)?,
        );

        // Verificar se o endereço tem saldo suficiente para a taxa
        let kybl_balance = self
            .blockchain
            .tokens
            .get(&0.to_string())
            .ok_or(anyhow::anyhow!("Token KYBL não encontrado"))?
            .balances
            .get(&owner)
            .copied()
            .unwrap_or(0);

        if kybl_balance < token_creation_fee {
            return Err(anyhow::anyhow!(
                "Saldo insuficiente de KYBL para criar token. Mínimo: {}",
                token_creation_fee
            )
            .into());
        }

        // Limitar tokens por conta (exemplo: consultar banco de dados)
        let conn = self.database.get_connection()?;
        let token_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tokens WHERE creator = ?1",
            [&owner],
            |row| row.get(0),
        )?;

        let max_tokens_per_account = 5;
        if token_count >= max_tokens_per_account {
            return Err(anyhow::anyhow!(
                "Limite máximo de {} tokens por conta atingido",
                max_tokens_per_account
            )
            .into());
        }

        // Cobra a taxa em KYBL
        let kybl_token = self
            .blockchain
            .tokens
            .get_mut(&0.to_string())
            .ok_or(anyhow::anyhow!("Token KYBL não encontrado"))?;

        *kybl_token.balances.entry(owner.clone()).or_insert(0) -= token_creation_fee;
        *kybl_token.balances.entry("system".to_string()).or_insert(0) += token_creation_fee;

        // Criar o token customizado
        let mut token = CustomToken::new(id, name.clone(), symbol.clone(), supply, owner.clone())?;

        // Assinando a transação de criação
        let data = format!("create_token:{}:{}:{}:{}", name, symbol, supply, owner);
        token.sign_transaction(&data)?;

        // Registra o token no banco de dados
        let conn = self.database.get_connection_mut()?;
        conn.execute(
            "INSERT INTO tokens (name, symbol, supply, creator) VALUES (?1, ?2, ?3, ?4)",
            params![token.name, token.symbol, supply, token.owner],
        )?;

        Ok(token)
    }

    fn calculate_token_creation_fee(
        &self,
        symbol_length: usize,
        supply: u64,
        creator_reputation: u64,
    ) -> u64 {
        // Taxa base - depende do comprimento do símbolo (símbolos premium custam mais)
        let base_fee = match symbol_length {
            2 => TOKEN_CREATION_BASE_FEE_2CHAR,
            3 => TOKEN_CREATION_BASE_FEE_3CHAR,
            4 => TOKEN_CREATION_BASE_FEE_4CHAR,
            _ => TOKEN_CREATION_BASE_FEE_DEFAULT,
        };

        // Componente baseado no supply (0.01% do supply inicial, max 1000 KYBL)
        let supply_component = std::cmp::min(supply / 10000, 1000);

        // Desconto baseado na reputação do criador
        let reputation_discount = std::cmp::min(creator_reputation / 100, 50); // Max 50% de desconto
        let discount_multiplier = (100 - reputation_discount) as f64 / 100.0;

        // Cálculo final com desconto aplicado
        let fee = (base_fee + supply_component) as f64 * discount_multiplier;

        fee as u64
    }

    // Função para distribuir as taxas coletadas
    fn distribute_fees(&mut self, fee_amount: u64) -> Result<()> {
        let kybl_token = self
            .blockchain
            .tokens
            .get_mut(&0.to_string())
            .ok_or(anyhow::anyhow!("Token KYBL não encontrado"))?;

        // Cálculo dos valores de distribuição
        let burn_amount = (fee_amount * BURN_PERCENTAGE) / 100;
        let staking_amount = (fee_amount * STAKING_PERCENTAGE) / 100;
        let dev_amount = (fee_amount * DEV_PERCENTAGE) / 100;
        // Usando a subtração para garantir que todas as taxas sejam distribuídas sem erro de arredondamento
        let liquidity_amount = fee_amount - burn_amount - staking_amount - dev_amount;

        // Atualizar balances
        kybl_token.total_supply -= burn_amount; // Queima direta
        *kybl_token
            .balances
            .entry(STAKING_POOL_ADDRESS.to_string())
            .or_insert(0) += staking_amount;
        *kybl_token
            .balances
            .entry(DEV_FUND_ADDRESS.to_string())
            .or_insert(0) += dev_amount;
        *kybl_token
            .balances
            .entry(LIQUIDITY_FUND_ADDRESS.to_string())
            .or_insert(0) += liquidity_amount;

        // Registrar a distribuição (log)
        info!("Distribuição de taxa: Queima: {} KYBL, Staking: {} KYBL, Dev: {} KYBL, Liquidez: {} KYBL",
              burn_amount, staking_amount, dev_amount, liquidity_amount);

        // Se o banco de dados estiver configurado, registre a distribuição lá também
        if let Ok(conn) = self.database.get_connection() {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            // Ignorar erro se a tabela ainda não existir
            let _ = conn.execute(
                "INSERT INTO fee_distributions (timestamp, burn_amount, staking_amount, dev_amount, liquidity_amount) 
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![timestamp, burn_amount, staking_amount, dev_amount, liquidity_amount],
            );
        }

        Ok(())
    }

    // Função para obter reputação do criador
    fn get_creator_reputation(&self, address: &str) -> Result<u64> {
        // Implementação básica - retorna 0 se o banco de dados não estiver acessível
        let reputation = match self.database.get_connection() {
            Ok(conn) => {
                // Tentar obter pelo número de transações bem-sucedidas
                conn.query_row(
                    "SELECT COUNT(*) FROM transactions WHERE from_address = ?1",
                    [address],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0) as u64
                    * 10 // 10 pontos por transação
            }
            Err(_) => 0, // Se o banco de dados não estiver acessível, reputação zero
        };

        Ok(reputation)
    }

    pub fn transfer_token(
        &mut self,
        token: &mut CustomToken,
        to: String,
        amount: u64,
        secret_key: &dilithium5::SecretKey,
    ) -> Result<SecureTransaction> {
        // Validações básicas
        if amount == 0 {
            return Err(anyhow::anyhow!("Quantidade deve ser maior que zero").into());
        }

        // Taxa de transferência: 0.1% do valor transferido (mínimo 1 KYBL)
        let transfer_fee = std::cmp::max(amount / TRANSFER_FEE_DIVISOR, TRANSFER_FEE_MINIMUM);

        // Verificar saldo KYBL para pagamento da taxa
        let from = token.owner.clone();
        let kybl_balance = self
            .blockchain
            .tokens
            .get(&0.to_string())
            .ok_or(anyhow::anyhow!("Token KYBL não encontrado"))?
            .balances
            .get(&from)
            .copied()
            .unwrap_or(0);

        if kybl_balance < transfer_fee {
            return Err(anyhow::anyhow!(
                "Saldo insuficiente de KYBL para taxa de transferência. Necessário: {} KYBL",
                transfer_fee
            )
            .into());
        }

        // Cobra a taxa
        let kybl_token = self
            .blockchain
            .tokens
            .get_mut(&0.to_string())
            .ok_or(anyhow::anyhow!("Token KYBL não encontrado"))?;

        *kybl_token.balances.entry(from.clone()).or_insert(0) -= transfer_fee;

        // Distribuir as taxas
        self.distribute_fees(transfer_fee)?;

        // Executa a transferência do token original
        token.transfer(to.clone(), amount)?;

        // Registra no banco de dados
        let conn = self
            .database
            .get_connection_mut()
            .context("Falha ao obter conexão com banco de dados")?;

        conn.execute(
        "INSERT INTO transfers (token_id, from_address, to_address, amount) VALUES (?1, ?2, ?3, ?4)",
        params![token.id, token.owner, to.clone(), amount],
    ).context("Falha ao registrar transferência no banco de dados")?;

        // Criar uma transação segura para retornar
        let public_key = self.blockchain.get_public_key(&from)?;
        let nonce = self.blockchain.nonces.get(&from).copied().unwrap_or(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Incluir informação da taxa na transação segura
        let transaction = SecureTransaction::new(
            from,
            to.clone(), // Clone aqui para evitar o erro de move
            amount,
            timestamp,
            nonce + 1,
            secret_key,
            &public_key,
        )?;

        // Log da transferência e taxa
        info!(
            "Transferência de {} tokens (ID: {}) para {}. Taxa: {} KYBL",
            amount, token.id, to, transfer_fee
        );

        Ok(transaction)
    }

    pub fn verify_chain_integrity(&self) -> Result<bool> {
        self.blockchain
            .is_chain_valid()
            .context("Falha ao verificar integridade da blockchain")
    }
}
