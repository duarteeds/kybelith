pub mod app;
pub mod blockchain;
pub mod config;
pub mod consensus;
pub mod constants;
pub mod database;
pub mod error;
pub mod key_manager;
pub mod quantum_crypto;
pub mod smart_contract;
pub mod token;
pub mod transaction;
pub mod utils;
pub mod p2p;
pub mod crypto;

// Re-exports principais
pub use app::QuantumBlockchainApp;
pub use blockchain::Blockchain;
pub use database::Database;
pub use error::TransactionError;
pub use key_manager::KeyManager;
pub use quantum_crypto::quantum_crypto::OqsError;
pub use quantum_crypto::QuantumCrypto;
pub use smart_contract::SmartContract;
pub use token::Token;
pub use transaction::{
    NonceRegistry, TransactionProcessor, TransactionSigner, TransactionVerifier,
};


// Constantes globais
pub const BLOCKCHAIN_FILE: &str = "blockchain.json";
pub const DB_PATH: &str = "blockchain.db";
