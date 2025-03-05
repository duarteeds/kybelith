#[cfg(test)]
mod tests {
    use kybelith::crypto::kyber::Kyber512;

    #[test]
    fn test_kyber512_encapsulation() -> Result<(), String> {
        let kyber = Kyber512::new().map_err(|e| format!("Failed to init Kyber512: {}", e))?;
        let (public_key, _secret_key) = kyber.keypair().map_err(|e| format!("Failed to generate keypair: {}", e))?;
        let public_key_bytes = public_key.into_vec();
        assert_eq!(public_key_bytes.len(), 800, "Public key length incorrect");
        let (shared_secret, ciphertext) = kyber.encapsulate(&public_key_bytes)
            .map_err(|e| format!("Encapsulation failed: {}", e))?;
        assert_eq!(shared_secret.len(), 32, "Shared secret length incorrect");
        assert_eq!(ciphertext.len(), 768, "Ciphertext length incorrect");
        Ok(())
    }
}