use anyhow::{Context, Result};
use log::info;
use rusqlite::Connection;
use std::path::Path;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(db_path: &str) -> Result<Self> {
        let path = Path::new(db_path);
        let create_new = !path.exists();

        let conn =
            Connection::open(db_path).context("Falha ao abrir conexão com banco de dados")?;

        let db = Database { conn };

        if create_new {
            db.initialize_tables()
                .context("Falha ao inicializar tabelas")?;
        }

        Ok(db)
    }

    fn initialize_tables(&self) -> Result<()> {
        info!("Criando tabela transactions...");
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK (amount > 0),
                timestamp INTEGER NOT NULL,
                signature BLOB NOT NULL,
                public_key BLOB NOT NULL
            )",
                [],
            )
            .context("Falha ao criar tabela transactions")?;

        info!("Criando tabela tokens...");
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                symbol TEXT NOT NULL,
                supply INTEGER NOT NULL,
                creator TEXT NOT NULL
            )",
                [],
            )
            .context("Falha ao criar tabela tokens")?;

        info!("Criando tabela fee_distributions...");
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS fee_distributions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            burn_amount INTEGER NOT NULL,
            staking_amount INTEGER NOT NULL,
            dev_amount INTEGER NOT NULL,
            liquidity_amount INTEGER NOT NULL
        )",
                [],
            )
            .context("Falha ao criar tabela fee_distributions")?;

        info!("Criando tabela transfers...");
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id INTEGER NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY(token_id) REFERENCES tokens(id)
            )",
                [],
            )
            .context("Falha ao criar tabela transfers")?;

        info!("Criando índices...");
        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions (from_address)",
                [],
            )
            .context("Falha ao criar índice em transactions.from_address")?;

        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions (to_address)",
                [],
            )
            .context("Falha ao criar índice em transactions.to_address")?;

        Ok(())
    }

    pub fn get_connection_mut(&mut self) -> Result<&mut Connection> {
        Ok(&mut self.conn)
    }

    pub fn get_connection(&self) -> Result<&Connection> {
        Ok(&self.conn)
    }

    pub fn insert_transaction(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        timestamp: i64,
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO transactions (from_address, to_address, amount, timestamp, signature, public_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![from, to, amount, timestamp, signature, public_key],
        ).context("Falha ao inserir transação")?;
        Ok(())
    }

    pub fn get_transactions_by_address(
        &self,
        address: &str,
    ) -> Result<Vec<(String, String, u64, i64)>> {
        let mut stmt = self.conn.prepare(
        "SELECT from_address, to_address, amount, timestamp FROM transactions WHERE from_address = ?1 OR to_address = ?1",
    )?;

        let rows = stmt.query_map(rusqlite::params![address], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;

        // Mapeia rusqlite::Error para anyhow::Error
        let transactions: Vec<_> = rows
            .map(|result| result.map_err(|e| anyhow::anyhow!("Erro ao acessar linha: {}", e)))
            .collect::<Result<Vec<_>>>()?;

        Ok(transactions)
    }
}
