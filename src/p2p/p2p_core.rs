
use std::sync::{Arc, Mutex};
use log::{info, warn, error};
use crate::p2p::network::SecureNetworkManager;
use crate::p2p::discovery::EnhancedNodeDiscovery;
use crate::p2p::interop::bridge::{ExternalChainInfo, ConnectionStatus};
use crate::p2p::interop::protocol::CrossChainTxType;
use crate::p2p::types::{NodeId, NodeInfo};
use crate::p2p::interop::bridge::BlockchainProtocol;
use crate::p2p::interop::protocol::convert_address;


use crate::p2p::{
    BridgeManager,
    InteropProtocol,
    Message,
    MessageType,
};
use crate::crypto::{
    kyber::Kyber512,
    dilithium::Dilithium5,
    hash::quantum_resistant_hash,
};


/// P2P Network Configuration
pub struct P2PConfig {
    /// Local node ID
    pub node_id: String,
    /// Listen address (IP:port)
    pub listen_address: String,
    /// Seed nodes to connect to on startup
    pub seed_nodes: Vec<String>,
    /// Path to node cache file
    pub node_cache_path: Option<String>,
    /// Maximum number of connections
    pub max_connections: usize,
    /// Enable cross-chain bridges
    pub enable_bridges: bool,
    /// Trusted peers (don't need validation)
    pub trusted_peers: Vec<String>,
}

/// Complete P2P Network Stack with enhanced security
pub struct EnhancedP2PNetwork {
    /// Secure network manager
    network: Arc<SecureNetworkManager>,
    /// Bridge manager for cross-chain communication
    bridge_manager: Option<Arc<Mutex<BridgeManager>>>,
    /// Node discovery service
    discovery: Arc<EnhancedNodeDiscovery>,
    /// Interoperability protocol
    interop: Option<InteropProtocol>,
    /// Configuration
    config: P2PConfig,
    /// Cryptographic components
    kyber: Kyber512,
    dilithium: Dilithium5,
    local_id: NodeId,
    private_key: Vec<u8>,
}

impl EnhancedP2PNetwork {
    /// Create a new enhanced P2P network
    pub fn new(config: P2PConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing enhanced P2P network with ID: {}", config.node_id);

        // Defina local_id uma única vez
        let local_id = config.node_id.clone();

        // Inicialize o BridgeManager
        let bridge_manager = if config.enable_bridges {
            let manager = BridgeManager::new(local_id.clone())?; // Use o local_id aqui
            Some(Arc::new(Mutex::new(manager)))
        } else {
            None
        };

        // Inicialize os componentes criptográficos
        let kyber = Kyber512::new()?;
        let dilithium = Dilithium5::new()?;

        // Gere o par de chaves
        let (public_key, private_key) = dilithium.keypair()?;

        // Crie o EnhancedNodeDiscovery
        let discovery = if let Some(cache_path) = &config.node_cache_path {
            Arc::new(
                EnhancedNodeDiscovery::new(local_id.clone())
                    .with_cache_file(cache_path)
                    .with_seeds(config.trusted_peers.clone())
            )
        } else {
            Arc::new(
                EnhancedNodeDiscovery::new(local_id.clone())
                    .with_seeds(config.trusted_peers.clone())
            )
        };

        // Crie o SecureNetworkManager
        let network = Arc::new(
            SecureNetworkManager::new(
                &config.listen_address,
                local_id.clone(), // Use o local_id aqui
                public_key.clone(),
            )?
        );

        // Crie o InteropProtocol (se necessário)
        let interop = if config.enable_bridges {
            Some(InteropProtocol::new()?)
        } else {
            None
        };

        Ok(Self {
            network,
            bridge_manager, // Armazene o bridge_manager aqui
            discovery,
            interop,
            config,
            kyber,
            dilithium,
            private_key,
            local_id, // Armazene o local_id aqui
        })
    }

    
    /// Start the P2P network
   pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting enhanced P2P network");

    // Inicie o SecureNetworkManager
    self.network.start()?;

    // Carregue o cache de descoberta de nós
    if let Err(e) = self.discovery.load_node_cache() {
        error!("Failed to load node cache: {}", e);
    }

    // Conecte-se aos nós seed
    for seed in &self.config.seed_nodes {
        match self.network.connect_to_node(seed) {
            Ok(node_id) => {
                info!("Connected to seed node {} at {}", node_id, seed);

                // Envie uma solicitação de descoberta ao nó seed
                let discovery_request = Message {
                    sender: self.local_id.clone(), // Use o local_id aqui
                    message_type: MessageType::DiscoveryRequest,
                    payload: Vec::new(),
                    is_compressed: false,
                };

                if let Err(e) = self.network.send_message(&node_id, discovery_request) {
                    error!("Failed to send discovery request to {}: {}", node_id, e);
                }
            }
            Err(e) => {
                error!("Failed to connect to seed node {}: {}", seed, e);
            }
        }
    }

    // Inicie o serviço de descoberta
    if let Err(e) = self.discovery.start_discovery(Arc::clone(&self.network)) {
        error!("Failed to start discovery service: {}", e);
    }

    // Inicialize o BridgeManager (se habilitado)
    if let Some(bridge_manager) = &self.bridge_manager {
        let mut manager = bridge_manager.lock().unwrap();

        // Integre o BridgeManager com o NetworkManager
        if let Err(e) = manager.integrate_with_network(Arc::new(Mutex::new((*self.network).clone()))) {
            error!("Failed to integrate bridge manager with network: {}", e);
        }

        // Configure as pontes padrão
        self.setup_default_bridges(&mut manager)?;

        // Conecte todas as pontes
        for result in manager.connect_all() {
            if let Err(e) = result {
                error!("Failed to connect to blockchain bridge: {}", e);
            }
        }

        info!("Bridge manager initialized with {} bridges", manager.get_bridges_info().len());
    }

    info!("Enhanced P2P network started successfully");
    Ok(())
}

/// Método para rotacionar chaves na rede P2P e no bridge manager
pub fn rotate_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Iniciando rotação de chaves");

        // Rotacionar chaves no bridge_manager se disponível
        if let Some(bridge_manager) = &self.bridge_manager {
            let manager = bridge_manager.lock().unwrap();
            if let Err(e) = manager.rotate_keys() {
                warn!("Falha na rotação de chaves do bridge_manager: {}", e);
            }
        }

        // Gerar novas chaves para a rede P2P
        let dilithium = Dilithium5::new()?;
        let (new_public_key, new_private_key) = dilithium.keypair()?;

        // Atualizar a chave privada local
        self.private_key = new_private_key; // Agora usamos a nova chave privada

        // Serializar para broadcast
        let key_rotation_payload = bincode::serialize(&new_public_key)?;

        // Enviar para todos os nós conectados
        self.broadcast_message(MessageType::KeyRotation, key_rotation_payload)?;

        info!("Rotação de chaves concluída com sucesso");
        Ok(())
    }

/// Método para iniciar o scheduler de rotação de chaves
pub fn start_key_rotation_scheduler(self: Arc<Self>, interval_mins: u64) -> Result<(), String> {
    let interval = interval_mins;
    
    // Criar clones das estruturas necessárias para a thread
    let network = Arc::clone(&self);
    let bridge = self.bridge_manager.clone();
    
    std::thread::spawn(move || {
        info!("Iniciando scheduler de rotação de chaves, intervalo: {} minutos", interval);
        
        loop {
            std::thread::sleep(std::time::Duration::from_secs(interval * 60));
            info!("Executando rotação programada de chaves");
            
            // Rotacionar chaves no bridge_manager
            if let Some(bridge_manager) = &bridge {
                if let Ok(manager) = bridge_manager.lock() {
                    if let Err(e) = manager.rotate_keys() {
                        error!("Falha na rotação de chaves do bridge_manager: {}", e);
                    }
                }
            }
            
            // Rotacionar chaves da rede - use Arc diretamente
            let network_ref = network.clone();
            
            // Gerar novas chaves
            let dilithium = match Dilithium5::new() {
                Ok(d) => d,
                Err(e) => {
                    error!("Falha ao criar instância Dilithium: {}", e);
                    continue;
                }
            };
            
            match dilithium.keypair() {
                Ok((new_public_key, _new_private_key)) => {
                    // Serializar para broadcast
                    match bincode::serialize(&new_public_key) {
                        Ok(key_data) => {
                            // Criar mensagem
                            let message = Message {
                                sender: network_ref.local_id.clone(),
                                message_type: MessageType::KeyRotation,
                                payload: key_data,
                                is_compressed: false,
                            };
                            
                            // Enviar mensagem
                            if let Err(e) = network_ref.broadcast_message(message.message_type, message.payload) {
                                error!("Falha ao broadcast da rotação de chaves: {}", e);
                            }
                        },
                        Err(e) => error!("Falha ao serializar chave pública: {}", e),
                    }
                },
                Err(e) => error!("Falha ao gerar par de chaves: {}", e),
            }
        }
    });
    
    Ok(())
}


/// Método para obter informações sobre todas as bridges
pub fn get_bridges_info(&self) -> Vec<ExternalChainInfo> {
    if let Some(bridge_manager) = &self.bridge_manager {
        if let Ok(manager) = bridge_manager.lock() {
            return manager.get_bridges_info();
        }
    }
    Vec::new()
}
    
    /// Setup default bridges
 pub fn setup_default_bridges(&self, manager: &mut BridgeManager) -> Result<(), Box<dyn std::error::Error>> {
    // Add bridge to Ethereum
    let ethereum_info = ExternalChainInfo {
        name: "Ethereum".to_string(),
        protocol: BlockchainProtocol::Ethereum,
        connection_address: "eth-bridge.kybelith.network:8545".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "PoS".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(ethereum_info) {
        error!("Failed to add Ethereum bridge: {}", e);
        return Err(e.into());
    }
    
    // Add bridge to Polkadot
    let polkadot_info = ExternalChainInfo {
        name: "Polkadot".to_string(),
        protocol: BlockchainProtocol::Polkadot,
        connection_address: "dot-bridge.kybelith.network:9944".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "NPoS".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(polkadot_info) {
        error!("Failed to add Polkadot bridge: {}", e);
        return Err(e.into());
    }

    // Add bridge to Bitcoin
    let bitcoin_info = ExternalChainInfo {
        name: "Bitcoin".to_string(),
        protocol: BlockchainProtocol::Bitcoin,
        connection_address: "btc-bridge.kybelith.network:8333".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "PoW".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(bitcoin_info) {
        error!("Failed to add Bitcoin bridge: {}", e);
        return Err(e.into());
    }

    // Add bridge to Cardano
    let cardano_info = ExternalChainInfo {
        name: "Cardano".to_string(),
        protocol: BlockchainProtocol::Cardano,
        connection_address: "ada-bridge.kybelith.network:3001".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "PoS".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(cardano_info) {
        error!("Failed to add Cardano bridge: {}", e);
        return Err(e.into());
    }

    // Add bridge to Binance Smart Chain (BSC)
    let bsc_info = ExternalChainInfo {
        name: "Binance Smart Chain".to_string(),
        protocol: BlockchainProtocol::BinanceSmartChain,
        connection_address: "bsc-bridge.kybelith.network:8546".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "PoSA".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(bsc_info) {
        error!("Failed to add Binance Smart Chain bridge: {}", e);
        return Err(e.into());
    }

    // Add bridge to Solana
    let solana_info = ExternalChainInfo {
        name: "Solana".to_string(),
        protocol: BlockchainProtocol::Solana,
        connection_address: "sol-bridge.kybelith.network:8900".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "PoH".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(solana_info) {
        error!("Failed to add Solana bridge: {}", e);
        return Err(e.into());
    }

    // Add bridge to Avalanche
    let avalanche_info = ExternalChainInfo {
        name: "Avalanche".to_string(),
        protocol: BlockchainProtocol::Avalanche,
        connection_address: "avax-bridge.kybelith.network:9651".to_string(),
        protocol_version: "1.0".to_string(),
        consensus_type: "Snowman".to_string(),
        last_sync: 0,
        connection_status: ConnectionStatus::Disconnected,
    };
    
    if let Err(e) = manager.add_bridge(avalanche_info) {
        error!("Failed to add Avalanche bridge: {}", e);
        return Err(e.into());
    }
    
    Ok(())
}
    
    /// Send a message to a specific node
    pub fn send_message(&self, node_id: &NodeId, message_type: MessageType, payload: Vec<u8>) 
        -> Result<(), Box<dyn std::error::Error>> {
        
        let message = Message {
            sender: self.network.as_ref().local_id().clone(),
            message_type,
            payload,
            is_compressed: false,
        };
        
        self.network.send_message(node_id, message)
    }
    
    /// Broadcast a message to all connected nodes
    pub fn broadcast_message(&self, message_type: MessageType, payload: Vec<u8>) 
        -> Result<usize, Box<dyn std::error::Error>> {
        
        let message = Message {
            sender: self.network.as_ref().local_id().clone(),
            message_type,
            payload,
            is_compressed: false,
        };
        
        self.network.broadcast_message(message)
    }
    
    /// Get all connected nodes
    pub fn get_connected_nodes(&self) -> Vec<NodeInfo> {
        self.network.get_connected_nodes()
    }
    
    /// Get all known nodes (connected or not)
    pub fn get_known_nodes(&self) -> Vec<NodeInfo> {
        self.discovery.get_all_nodes()
    }
    
    /// Create a cross-chain transaction
    pub fn create_cross_chain_transaction(
        &self,
        target_chain: &str,
        tx_type: CrossChainTxType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Check if bridges are enabled
        let interop = self.interop.as_ref()
            .ok_or("Cross-chain functionality not enabled")?;
            
        let bridge_manager = self.bridge_manager.as_ref()
            .ok_or("Bridge manager not enabled")?
            .lock()
            .unwrap();
        
        // Create transaction
        let transaction = interop.create_transaction(
            "Kybelith".to_string(),
            target_chain.to_string(),
            tx_type,
        )?;
        
        // Send transaction through bridge
        let tx_id = interop.send_transaction(transaction, &bridge_manager)?;
        
        Ok(tx_id)
    }
    
    /// Convert an address from one blockchain format to another
    pub fn convert_address(
    &self,
    address: &str,
    from_chain: BlockchainProtocol,
    to_chain: BlockchainProtocol,
) -> Result<String, String> {
    if self.interop.is_none() {
        return Err("Cross-chain functionality not enabled".to_string());
    }
    convert_address(address, &from_chain, &to_chain)
}
    
    /// Stop the P2P network
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Stopping enhanced P2P network");
        
        // Stop discovery service
        self.discovery.stop_discovery();
        
        // Stop network manager
        self.network.stop()?;
        
        // Save discovery cache
        if let Err(e) = self.discovery.save_node_cache() {
            error!("Failed to save node cache: {}", e);
        }
        
        // Disconnect bridges if enabled
        if let Some(bridge_manager) = &self.bridge_manager {
            let bridges = bridge_manager.lock().unwrap().get_bridges_info();
            
            for bridge in bridges {
                if let Err(e) = bridge_manager.lock().unwrap().remove_bridge(&bridge.name) {
                    error!("Failed to remove bridge {}: {}", bridge.name, e);
                }
            }
        }
        
        info!("Enhanced P2P network stopped successfully");
        Ok(())
    }
    
    /// Generate a quantum-resistant signature
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate a key pair if needed
    let (_, private_key) = self.dilithium.keypair()?;
    
    // Sign the data
    let signature = self.dilithium.sign(data, &private_key)?;
    
    Ok(signature)
}
    
    /// Verify a quantum-resistant signature
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.dilithium.verify(data, signature, public_key)
    }
    
    /// Create a secure shared secret with a peer
    pub fn create_shared_secret(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Encapsulate a shared secret using Kyber
        let (shared_secret, _) = self.kyber.encapsulate(peer_public_key)?;
        
        // Apply additional hashing for extra security
        let hashed_secret = quantum_resistant_hash(&shared_secret);
        
        Ok(hashed_secret)
    }
}

/// Usage example for the enhanced P2P network
pub fn run_p2p_network() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = P2PConfig {
        node_id: format!("node_{}", uuid::Uuid::new_v4()),
        listen_address: "0.0.0.0:12345".to_string(),
        seed_nodes: vec![
            "seed1.kybelith.network:12345".to_string(),
            "seed2.kybelith.network:12345".to_string(),
        ],
        node_cache_path: Some("./node_cache.bin".to_string()),
        max_connections: 50,
        enable_bridges: true,
        trusted_peers: vec![
            "trusted1.kybelith.network".to_string(),
            "trusted2.kybelith.network".to_string(),
        ],
    };
    
    // Create and start the network
    let network = EnhancedP2PNetwork::new(config)?;
    network.start()?;
    
    // Keep running until terminated
    info!("Network running, press Ctrl+C to stop");
    
    // Example: Wait for signal to stop
    // In a real application, you'd integrate with your main program loop
    std::thread::sleep(std::time::Duration::from_secs(3600));
    
    // Stop the network
    network.stop()?;
    
    Ok(())
}