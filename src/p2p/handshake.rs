use std::time::{SystemTime, UNIX_EPOCH};
use crate::p2p::types::NodeInfo;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use std::error::Error;
use serde::{Serialize, Deserialize};
use oqs::kem::Algorithm as KemAlgorithm;
use oqs::sig::Algorithm as SigAlgorithm;
use std::sync::Arc;
use rand::RngCore;
use sha3::Digest;
use crate::p2p::NodeId;


impl Clone for Handshake {
    fn clone(&self) -> Self {
        Self {
           kem: Arc::clone(&self.kem), // Compartilha a mesma instância de Kem
            sig: Arc::clone(&self.sig), // Compartilha a mesma instância de Sig
            sk: self.sk.clone(),        // Clona a SecretKey (se implementar Clone)   
        }
    }
}

pub struct Handshake {
    kem: Arc<oqs::kem::Kem>,
    sig: Arc<oqs::sig::Sig>,
    sk: oqs::sig::SecretKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HandshakeMessage {
    protocol_version: String,    
    public_key: Vec<u8>,
    signature: Vec<u8>,
    nonce: [u8; 32],
    timestamp: u64,
}

impl Handshake {

// Version to use for all handshake messages
    const PROTOCOL_VERSION: &'static str = "1.0.0";
// Maximum age of a handshake before rejection (milliseconds)
    const MAX_TIMESTAMP_DIFF_MS: u64 = 30000; // 30 seconds

    pub fn new() -> Result<Self, Box<dyn Error>> {
        let kem = Arc::new(oqs::kem::Kem::new(KemAlgorithm::Kyber512)?);
        let sig = Arc::new(oqs::sig::Sig::new(SigAlgorithm::Dilithium5)?);
        let (_, sk) = sig.keypair()?;

        Ok(Self { kem, sig, sk })
    }

     pub fn perform_enhanced_handshake(
    &self,
    local_node: &NodeInfo,
    remote_node: &NodeInfo,
    remote_data: &[u8],
) -> Result<(Vec<u8>, ChaCha20Poly1305, Vec<u8>), Box<dyn std::error::Error>> {
    // Gerar par de chaves efêmero
    let (ephemeral_pk, _ephemeral_sk) = self.kem.keypair()?;
    let ephemeral_pk_vec = ephemeral_pk.into_vec();
    
    // Gerar nonce
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    
    // Dados adicionais para assinatura
    let mut additional_data = ephemeral_pk_vec.clone();
    additional_data.extend_from_slice(&nonce);
    
    // Assinar dados adicionais - crucial para autenticação quântica
    let _ephemeral_signature = self.sig.sign(&additional_data, &self.sk)?;

    // Timestamp para prevenção de replay attacks
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis() as u64;
    
    // Buffer de identidade para assinatura
    let mut identity_buffer = Vec::new();
    identity_buffer.extend_from_slice(local_node.id.as_bytes());
    identity_buffer.extend_from_slice(&ephemeral_pk_vec);
    identity_buffer.extend_from_slice(&nonce);
    identity_buffer.extend_from_slice(&timestamp.to_be_bytes());
    
    // Assinatura Dilithium - resistente a ataques quânticos
    let signature = self.sig.sign(&identity_buffer, &self.sk)?;

    // Mensagem de handshake
    let local_msg = HandshakeMessage {
    protocol_version: Self::PROTOCOL_VERSION.to_string(),  
    public_key: ephemeral_pk_vec,
    signature: signature.into_vec(),
    nonce,
    timestamp,
};
    
    let serialized_local = bincode::serialize(&local_msg)?;

    // Processar mensagem remota
    let remote_msg: HandshakeMessage = bincode::deserialize(remote_data)?;
    self.verify_enhanced_handshake(&remote_msg, remote_node)?;

    // Converter chave pública remota
    let remote_ephemeral_pk = self.kem.public_key_from_bytes(&remote_msg.public_key)
        .ok_or("Failed to convert remote ephemeral public key")?;
    
    // Encapsular usando KEM Kyber - troca de chaves resistente a quânticos
    let (ephemeral_secret, _) = self.kem.encapsulate(&remote_ephemeral_pk)?;
    let ephemeral_secret_vec = ephemeral_secret.into_vec();
    
    // Encapsular também com a chave estática para segurança adicional
    let remote_static_pk = self.kem.public_key_from_bytes(&remote_node.public_key)
        .ok_or("Failed to convert remote static public key")?;
    let (static_secret, _) = self.kem.encapsulate(&remote_static_pk)?;
    let static_secret_vec = static_secret.into_vec();

    // Combinar segredos com nonces para um segredo final mais forte
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&ephemeral_secret_vec);
    hasher.update(&static_secret_vec);
    hasher.update(&nonce);
    hasher.update(&remote_msg.nonce);
    let combined_secret = hasher.finalize().to_vec();

    // Criar cifra a partir do segredo combinado
    let cipher = ChaCha20Poly1305::new_from_slice(&combined_secret[..32])
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    Ok((combined_secret, cipher, serialized_local))
}

    // Enhanced handshake verification with additional security checks
    fn verify_enhanced_handshake(
    &self,
    msg: &HandshakeMessage,
    remote: &NodeInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Verificar versão do protocolo
    if msg.protocol_version != Self::PROTOCOL_VERSION {
        return Err(format!("Protocol version mismatch: expected {}, got {}", 
                         Self::PROTOCOL_VERSION, msg.protocol_version).into());
    }
    
    // 2. Validate timestamp to prevent replay attacks
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis() as u64;

    let timestamp_diff = if now > msg.timestamp {
        now - msg.timestamp
    } else {
        msg.timestamp - now // Clock skew case
    };

    if timestamp_diff > Self::MAX_TIMESTAMP_DIFF_MS {
        return Err(format!("Handshake timestamp too old or from future: diff={}ms", timestamp_diff).into());
    }

    // 3. Verify signature
    // Reconstruct the signed data
    let mut identity_buffer = Vec::new();
    identity_buffer.extend_from_slice(remote.id.as_bytes());
    identity_buffer.extend_from_slice(&msg.public_key);
    identity_buffer.extend_from_slice(&msg.nonce);
    identity_buffer.extend_from_slice(&msg.timestamp.to_be_bytes());

    // Convert signature and public key
    let signature = self.sig.signature_from_bytes(&msg.signature)
        .ok_or("Failed to convert signature")?;

    let public_key = self.sig.public_key_from_bytes(&remote.public_key)
        .ok_or("Failed to convert public key")?;

    // Verify the signature using Dilithium
    self.sig.verify(&identity_buffer, &signature, &public_key)?;

    Ok(())
}

}

// Enhanced handshake message structure
#[derive(Serialize, Deserialize, Debug)]
struct EnhancedHandshakeMessage {
    version: String,
    node_id: NodeId,
    ephemeral_public_key: Vec<u8>,
    static_public_key: Vec<u8>,
    nonce: [u8; 32],
    timestamp: u64,
    signature: Vec<u8>,
}