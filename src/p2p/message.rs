use serde::{Serialize, Deserialize};
use crate::p2p::types::{MessageType, NodeId};
use crate::p2p::network::SecureNetworkManager;
use log::info;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub sender: NodeId,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub is_compressed: bool, // Novo campo
}

impl Message {
    /// Serializa a mensagem para transmissão
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize message")
    }

    /// Desserializa a mensagem recebida
    pub fn deserialize(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        bincode::deserialize(data).map_err(|e| e.into())
    }

    /// Processa a mensagem, descomprimindo o payload se necessário
    pub fn handle_message(&self, network_manager: &SecureNetworkManager) -> Result<(), Box<dyn std::error::Error>> {
        // Descomprima o payload da mensagem (se necessário)
        let decompressed_payload = if self.is_compressed {
            network_manager.decompress_message(&self.payload, self.is_compressed)?
        } else {
            self.payload.clone() // Se não estiver comprimido, use o payload original
        };
        
        // Processe a mensagem descomprimida
        info!("Received message: {:?}", decompressed_payload);
        
        Ok(())
    }
}