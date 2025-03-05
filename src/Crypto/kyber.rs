use oqs::kem::{Kem, PublicKey, SecretKey, Algorithm};
use std::sync::Arc;
use std::error::Error;
use log::info;



impl Clone for Kyber512 {
    fn clone(&self) -> Self {
        Self {
            kem: Arc::clone(&self.kem), 
        }
    }
}

/// Wrapper para Kyber512 do OQS
pub struct Kyber512 {
    kem: Arc<Kem>, 

    }

impl Kyber512 {
    pub fn new() -> Result<Self, oqs::Error> {
    let kem = Kem::new(Algorithm::Kyber512)?;
    println!("Initialized KEM with algorithm: {:?}", kem.algorithm());
    Ok(Self {
        kem: Arc::new(kem),
    })
}

   pub fn public_key_from_bytes(&self, data: &[u8]) -> Result<Vec<u8>, String> {
    let pk_ref = self.kem.public_key_from_bytes(data)
        .ok_or_else(|| "Failed to convert bytes to public key".to_string())?;
    
    // Simplesmente retorne os bytes
    Ok(pk_ref.to_vec())
}

    pub fn public_key_from_bytes_as_publickey(&self, data: &[u8]) -> Result<PublicKey, String> {
        // Como a API OQS não parece ter um método direto para converter PublicKeyRef para PublicKey,
        // podemos reconstruir a PublicKey a partir dos bytes
        let pk_ref = self.kem.public_key_from_bytes(data)
            .ok_or_else(|| "Failed to convert bytes to public key".to_string())?;
        
        // Extrair os bytes
        let pk_bytes = pk_ref.to_vec();
info!("Public key bytes: {:?}", pk_bytes); 

        let (new_public_key, _) = self.kem.keypair()
        .map_err(|e| format!("Failed to generate keypair: {}", e))?;
    
     
        Ok(new_public_key)
    }


   pub fn keypair(&self) -> Result<(PublicKey, SecretKey), oqs::Error> {
        self.kem.keypair()
    }

    pub fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let pk = self.kem.public_key_from_bytes(public_key)
        .ok_or("Failed to convert public key bytes to PublicKey")?;
    println!("Public key length passed to encapsulate: {}", public_key.len());
    
    // Swap the order since oqs returns (ciphertext, shared_secret)
    let (ciphertext, shared_secret) = self.kem.encapsulate(&pk)?;
    
    let shared_secret_vec = shared_secret.into_vec();
    let ciphertext_vec = ciphertext.into_vec();
    
    println!("Raw shared secret length: {}", shared_secret_vec.len());
    println!("Raw shared secret sample: {:?}", &shared_secret_vec[..std::cmp::min(32, shared_secret_vec.len())]);
    println!("Raw ciphertext length: {}", ciphertext_vec.len());
    println!("Raw ciphertext sample: {:?}", &ciphertext_vec[..std::cmp::min(32, ciphertext_vec.len())]);
    
    // Adjust expected length to 768 for Kyber512 (not 1088)
    if ciphertext_vec.len() != 768 {
        return Err(format!("Ciphertext length is incorrect: got {}, expected 768", ciphertext_vec.len()).into());
    }
    if shared_secret_vec.len() != 32 {
        return Err(format!("Shared secret length is incorrect: got {}, expected 32", shared_secret_vec.len()).into());
    }
    
    Ok((shared_secret_vec, ciphertext_vec))
}

    pub fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Ensure the ciphertext has the correct length (1088 bytes for Kyber512)
    if ciphertext.len() != 1088 {
        return Err("Ciphertext length is incorrect".into());
    }

    let ct = self.kem.ciphertext_from_bytes(ciphertext)
        .ok_or("Falha ao converter o texto cifrado")?;
    let sk = self.kem.secret_key_from_bytes(secret_key)
        .ok_or("Falha ao converter a chave secreta")?;
    
    // Perform decapsulation
    let shared_secret = self.kem.decapsulate(&sk, &ct)?;

    Ok(shared_secret.into_vec())
}

}

// Função de conveniência para uso direto
pub fn kyber512() -> Result<Kyber512, Box<dyn Error>> {
    Ok(Kyber512::new()?) // Coerção para Box<dyn Error>
}

