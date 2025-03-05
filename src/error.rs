use bincode::ErrorKind;
use serde_json::Error as SerdeError;
use std::time::SystemTimeError;

#[derive(Debug)]
pub enum Error {
    TokenNotFound,
    InsufficientBalance,
    InvalidNonce,
    DuplicateTransaction,
    InvalidPublicKey,
    TransactionError(Box<TransactionError>),
    SerializationError(SerdeError),
    InvalidFormat(String),
    InvalidInput(String),
    TransactionTooLarge,
    InvalidTimestamp(String),
    InvalidSignature,
    LockError,
    NonceReused,
    BlockTooLarge,
    InvalidPreviousHash,
    InvalidAmount,
    DoubleSpending,
    InvalidAddress,
    BincodeSerializationError(Box<ErrorKind>),
    SystemTimeError(SystemTimeError),
    StaleBlock,
    CryptoError(String),
    TimeError(String),
    InvalidBlock(String),
    Other(String),
    OqsError(oqs::Error),
}

#[derive(Debug)]
pub enum TransactionError {
    OqsError(Box<oqs::Error>),
    InvalidTransaction,
    InvalidDataFormat,
    InsufficientFunds,
    NonceInvalido,
    InvalidTimestamp(String),
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
    NonceOverflow,
    AddressFormatInvalid,
    TimestampInvalid,
    InvalidInput(String),
    InvalidFormat(String),
    LockError,
    NonceReused,
    InvalidSignatures(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TokenNotFound => write!(f, "Token não encontrado"),
            Error::InsufficientBalance => write!(f, "Saldo insuficiente"),
            Error::InvalidNonce => write!(f, "Nonce inválido"),
            Error::DuplicateTransaction => write!(f, "Transação duplicada"),
            Error::InvalidPublicKey => write!(f, "Chave pública inválida"),
            Error::TransactionError(e) => write!(f, "Erro de transação: {}", e),
            Error::SerializationError(e) => write!(f, "Erro de serialização: {}", e),
            Error::InvalidFormat(e) => write!(f, "Formato inválido: {}", e),
            Error::InvalidInput(e) => write!(f, "Entrada inválida: {}", e),
            Error::TransactionTooLarge => write!(f, "Transação muito grande"),
            Error::InvalidTimestamp(e) => write!(f, "Timestamp inválido: {}", e),
            Error::InvalidSignature => write!(f, "Assinatura inválida"),
            Error::LockError => write!(f, "Erro de bloqueio"),
            Error::NonceReused => write!(f, "Nonce reutilizado"),
            Error::BlockTooLarge => write!(f, "Bloco muito grande"),
            Error::InvalidPreviousHash => write!(f, "Hash anterior inválido"),
            Error::InvalidAmount => write!(f, "Quantidade inválida"),
            Error::DoubleSpending => write!(f, "Tentativa de gasto duplo"),
            Error::InvalidAddress => write!(f, "Endereço inválido"),
            Error::BincodeSerializationError(e) => write!(f, "Erro de serialização bincode: {}", e),
            Error::SystemTimeError(e) => write!(f, "Erro de tempo do sistema: {}", e),
            Error::OqsError(e) => write!(f, "Erro OQS: {}", e),
            Error::StaleBlock => write!(f, "Bloco antigo"),
            Error::CryptoError(e) => write!(f, "Erro criptográfico: {}", e),
            Error::TimeError(e) => write!(f, "Erro de tempo: {}", e),
            Error::InvalidBlock(s) => write!(f, "Bloco inválido: {}", s),
            Error::Other(s) => write!(f, "Outro erro: {}", s),
        }
    }
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionError::OqsError(e) => write!(f, "Erro OQS: {}", e),
            TransactionError::InvalidTransaction => write!(f, "Transação inválida"),
            TransactionError::InvalidDataFormat => write!(f, "Formato de dados inválido"),
            TransactionError::InsufficientFunds => write!(f, "Fundos insuficientes"),
            TransactionError::NonceInvalido => write!(f, "Nonce inválido"),
            TransactionError::InvalidTimestamp(e) => write!(f, "Timestamp inválido: {}", e),
            TransactionError::EnderecoInvalido => write!(f, "Endereço inválido"),
            TransactionError::TokenNaoEncontrado => write!(f, "Token não encontrado"),
            TransactionError::TransacaoRepetida => write!(f, "Transação repetida"),
            TransactionError::ValorInvalido => write!(f, "Valor inválido"),
            TransactionError::InvalidSignature(e) => write!(f, "Assinatura inválida: {}", e),
            TransactionError::InvalidPublicKey(e) => write!(f, "Chave pública inválida: {}", e),
            TransactionError::InvalidData(e) => write!(f, "Dados inválidos: {}", e),
            TransactionError::Other(e) => write!(f, "Outro erro: {}", e),
            TransactionError::InvalidParameter(e) => write!(f, "Parâmetro inválido: {}", e),
            TransactionError::SignatureSizeExceeded => write!(f, "Tamanho da assinatura excedido"),
            TransactionError::DataSizeExceeded => write!(f, "Tamanho dos dados excedido"),
            TransactionError::NonceOverflow => write!(f, "Overflow de nonce"),
            TransactionError::AddressFormatInvalid => write!(f, "Formato de endereço inválido"),
            TransactionError::TimestampInvalid => write!(f, "Timestamp inválido"),
            TransactionError::InvalidInput(e) => write!(f, "Entrada inválida: {}", e),
            TransactionError::InvalidFormat(e) => write!(f, "Formato inválido: {}", e),
            TransactionError::LockError => write!(f, "Erro de bloqueio"),
            TransactionError::NonceReused => write!(f, "Nonce reutilizado"),
            TransactionError::InvalidSignatures(e) => write!(f, "Assinaturas inválidas: {}", e),
        }
    }
}

impl std::error::Error for Error {}
impl std::error::Error for TransactionError {}

impl From<SerdeError> for Error {
    fn from(err: SerdeError) -> Self {
        Error::SerializationError(err)
    }
}

impl From<oqs::Error> for TransactionError {
    fn from(err: oqs::Error) -> Self {
        TransactionError::OqsError(Box::new(err))
    }
}

impl From<TransactionError> for Error {
    fn from(err: TransactionError) -> Self {
        Error::TransactionError(Box::new(err))
    }
}

impl From<oqs::Error> for Error {
    fn from(err: oqs::Error) -> Self {
        Error::OqsError(err)
    }
}

impl From<Box<ErrorKind>> for Error {
    fn from(err: Box<ErrorKind>) -> Self {
        Error::BincodeSerializationError(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}

impl From<SystemTimeError> for Error {
    fn from(err: SystemTimeError) -> Self {
        Error::SystemTimeError(err)
    }
}
