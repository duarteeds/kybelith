
use oqs::sig::Algorithm;
use std::error::Error;
use std::sync::Arc;

impl Clone for Dilithium5 {
    fn clone(&self) -> Self {
        Self { sig: Arc::clone(&self.sig) }
    }
}

/// Wrapper para Dilithium5 do OQS
pub struct Dilithium5 {
    sig: Arc<oqs::sig::Sig>,
}

impl Dilithium5 {
    /// Cria uma nova instância de Dilithium5
    pub fn new() -> Result<Self, Box<dyn Error>> {
    let sig = Arc::new(oqs::sig::Sig::new(Algorithm::Dilithium5)?);
    Ok(Self { sig })
}

    /// Gera um par de chaves (pública e privada)
    pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let (public_key, secret_key) = self.sig.keypair()?;
        Ok((public_key.into_vec(), secret_key.into_vec()))
    }

    /// Assina uma mensagem usando a chave privada
    pub fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let sk = self.sig.secret_key_from_bytes(secret_key)
            .ok_or("Falha ao converter a chave secreta")?;
        
        let signature = self.sig.sign(message, &sk)?;
        Ok(signature.into_vec())
    }

    /// Verifica uma assinatura usando a chave pública
    pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Box<dyn Error>> {
        let pk = self.sig.public_key_from_bytes(public_key)
            .ok_or("Falha ao converter a chave pública")?;
        
        let sig = self.sig.signature_from_bytes(signature)
            .ok_or("Falha ao converter a assinatura")?;
        
        match self.sig.verify(message, &sig, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Função de conveniência para uso direto
pub fn dilithium5() -> Result<Dilithium5, Box<dyn Error>> {
    Dilithium5::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium5_signature() -> Result<(), Box<dyn Error>> {
        let dilithium = Dilithium5::new()?;
        
        // Gerar par de chaves
        let (public_key, secret_key) = dilithium.keypair()?;
        
        // Mensagem para assinar
        let message = b"Teste de assinatura com Dilithium5";
        
        // Assinar a mensagem
        let signature = dilithium.sign(message, &secret_key)?;
        
        // Verificar a assinatura
        let is_valid = dilithium.verify(message, &signature, &public_key)?;
        assert!(is_valid, "A assinatura deve ser válida");
        
        // Verificar com mensagem alterada
        let modified_message = b"Teste de assinatura com Dilithium5 - modificado";
        let is_valid = dilithium.verify(modified_message, &signature, &public_key)?;
        assert!(!is_valid, "A assinatura não deve ser válida para mensagem alterada");
        
        Ok(())
    }
}