use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;


/// Endereço de um nó na rede
pub type NodeAddress = SocketAddr;

/// ID único de um nó
pub type NodeId = String;

/// Estrutura que representa um nó na rede
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeInfo {
    pub id: NodeId,
    pub address: NodeAddress,
    pub public_key: Vec<u8>,
    pub services: HashSet<String>, 
    pub protocol_version: String,  
}

/// Enum para representar os tipos de mensagens P2P
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageType {
    Handshake,
    BlockProposal,
    Vote,
    CrossChainRequest,
    CrossChainResponse,
    DiscoveryRequest,
    DiscoveryResponse,
    Heartbeat,
    HeartbeatResponse,
    KeyRotation,
}