use crate::error::TransactionError;
use pqcrypto_dilithium::dilithium5::{sign, PublicKey, SecretKey};
use pqcrypto_traits::sign::SignedMessage;

pub struct TransactionSigner;

impl TransactionSigner {
    pub fn generate_keys() -> Result<(SecretKey, PublicKey), TransactionError> {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium5::keypair();
        Ok((secret_key, public_key))
    }

    pub fn sign(&self, data: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, TransactionError> {
        let signature = sign(data, secret_key);
        Ok(signature.as_bytes().to_vec())
    }
}
