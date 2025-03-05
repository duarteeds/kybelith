pub mod network;
pub mod message;
pub mod types;
pub mod handshake;
pub mod discovery;
pub mod interop;
pub mod spanning_tree;
pub mod p2p_core;


pub use handshake::Handshake;
pub use interop::{BridgeManager, InteropProtocol};
pub use message::Message;
pub use types::{NodeId, NodeInfo, MessageType};
pub use p2p_core::EnhancedP2PNetwork; 
pub use network::SecureNetworkManager as NetworkManager;
pub use discovery::EnhancedNodeDiscovery;