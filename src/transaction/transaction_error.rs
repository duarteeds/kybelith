use std::fmt;
use oqs::Error;

#[derive(Debug)]
pub enum TransactionError {
    OqsError(Error),
    InvalidTransaction,
    InvalidDataFormat,
    InsufficientFunds,
    NonceInvalido,
    InvalidTimestamp(String), // Variante corrigida
    EnderecoInvalido,
    TokenNaoEncontrado,
    TransacaoRepetida,
    ValorInvalido,
    InvalidSignature(String),
    InvalidPublicKey(String),
    InvalidData(String),
    Other(String),
    InvalidParameter(String),
    SignatureSizeExceeded,  
    DataSizeExceeded, 
}

// Defina InnerTransactionError ou substitua pelo tipo correto
#[derive(Debug)]
pub enum InnerTransactionError {
    SomeError,
    
}

// Implementação da trait From para conversão de InnerTransactionError
impl From<InnerTransactionError> for TransactionError {
    fn from(err: InnerTransactionError) -> Self {
        match err {
            InnerTransactionError::SomeError => TransactionError::Other("Some error occurred".to_string()),
            
        }
    }
}

// Implementação da trait Error para TransactionError
impl std::error::Error for TransactionError {}

// Implementação da trait Display para TransactionError
impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::OqsError(e) => write!(f, "OQS error: {}", e),
            TransactionError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            TransactionError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            TransactionError::InvalidTransaction => write!(f, "Invalid transaction"),
            TransactionError::InvalidDataFormat => write!(f, "Invalid data format"),
            TransactionError::InsufficientFunds => write!(f, "Insufficient funds"),
            TransactionError::NonceInvalido => write!(f, "Invalid nonce"),
            TransactionError::InvalidTimestamp(msg) => write!(f, "Invalid timestamp: {}", msg), // Corrigido
            TransactionError::EnderecoInvalido => write!(f, "Invalid address"),
            TransactionError::TokenNaoEncontrado => write!(f, "Token not found"),
            TransactionError::TransacaoRepetida => write!(f, "Duplicate transaction"),
            TransactionError::ValorInvalido => write!(f, "Invalid value"),
            TransactionError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            TransactionError::Other(msg) => write!(f, "Other error: {}", msg),
            TransactionError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            TransactionError::SignatureSizeExceeded => write!(f, "Signature size exceeded"),
            TransactionError::DataSizeExceeded => write!(f, "Data size exceeded"),

        }
    }
}