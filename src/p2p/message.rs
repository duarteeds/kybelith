use serde::{Serialize, Deserialize};
use crate::p2p::types::{MessageType, NodeId};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub sender: NodeId,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
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
}