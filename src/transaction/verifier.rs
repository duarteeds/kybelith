use crate::error::TransactionError;
use pqcrypto_dilithium::dilithium5::{verify_detached_signature, DetachedSignature, PublicKey};
use pqcrypto_traits::sign::DetachedSignature as PqcDetachedSignature;

pub struct TransactionVerifier;

impl TransactionVerifier {
    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        let signature = DetachedSignature::from_bytes(signature)
            .map_err(|_| TransactionError::InvalidSignatures("Invalid signature".to_string()))?;

        verify_detached_signature(&signature, data, public_key)
            .map_err(|_| TransactionError::InvalidSignatures("Invalid signature".to_string()))?;

        Ok(())
    }
}
