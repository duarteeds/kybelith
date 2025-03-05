// Constantes de segurança centralizadas
pub const MAX_TRANSACTION_SIZE: usize = 128 * 1024; // 128KB
pub const MAX_SIGNATURE_SIZE: usize = 4627; // Tamanho da assinatura Dilithium5
pub const MAX_TIME_DRIFT: i64 = 300; // 5 minutos
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024; // 1MB
pub const TIMESTAMP_WINDOW: i64 = 300; // 5 minutos para janela de timestamp
pub const MIN_ADDRESS_LENGTH: usize = 32;
pub const MAX_ADDRESS_LENGTH: usize = 64;
pub const HASH_SALT: &[u8] = b"QUANTUM_SECURE_TRANSACTION_V1";
pub const MIN_AMOUNT: u64 = 1;
pub const MAX_AMOUNT: u64 = 1_000_000_000;

// Endereços dos fundos para distribuição de taxas
pub const STAKING_POOL_ADDRESS: &str = "0xStakingPoolKybelithOfficial";
pub const DEV_FUND_ADDRESS: &str = "0xDevFundKybelithOfficial";
pub const LIQUIDITY_FUND_ADDRESS: &str = "0xLiquidityFundKybelithOfficial";

// Parâmetros de taxas para tokens
pub const TOKEN_CREATION_BASE_FEE_2CHAR: u64 = 1000;
pub const TOKEN_CREATION_BASE_FEE_3CHAR: u64 = 500;
pub const TOKEN_CREATION_BASE_FEE_4CHAR: u64 = 250;
pub const TOKEN_CREATION_BASE_FEE_DEFAULT: u64 = 100;

// Parâmetros de distribuição de taxas (em percentual)
pub const BURN_PERCENTAGE: u64 = 40;
pub const STAKING_PERCENTAGE: u64 = 30;
pub const DEV_PERCENTAGE: u64 = 20;
pub const LIQUIDITY_PERCENTAGE: u64 = 10;

// Taxa de transferência (percentual do valor, dividido por este número)
pub const TRANSFER_FEE_DIVISOR: u64 = 1000; // 0.1%
pub const TRANSFER_FEE_MINIMUM: u64 = 1; // Mínimo de 1 KYBL
