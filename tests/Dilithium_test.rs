#[cfg(test)]
mod tests {
    use kybelith::crypto::dilithium::Dilithium5;
    use std::error::Error;

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