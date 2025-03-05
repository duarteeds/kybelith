// Secure Network Manager with comprehensive security and reliability features
use std::collections::{HashMap, HashSet};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::io::{Read, Write, ErrorKind};
use rand::{RngCore, thread_rng};
use log::{info, warn, debug, error, trace};
use chacha20poly1305::{ChaCha20Poly1305, AeadCore, KeyInit, Key};
use chacha20poly1305::aead::Aead;
use crate::p2p::types::{NodeId, NodeInfo, MessageType};
use crate::p2p::message::Message;
use crate::p2p::handshake::Handshake;
use crate::p2p::discovery::EnhancedNodeDiscovery;
use crate::p2p::spanning_tree::SpanningTree;
use crate::crypto::kyber::Kyber512;
use crate::crypto::dilithium::Dilithium5;
use serde::{Serialize, Deserialize};
use crate::p2p::interop::bridge::CrossChainMessage;

impl Clone for SecureNetworkManager {
    fn clone(&self) -> Self {
        let listener_clone = self.listener.try_clone().expect("Failed to clone TCP listener");
        
        Self {
            nodes: Arc::clone(&self.nodes),
            metrics: Arc::clone(&self.metrics),
            listener: listener_clone,
            handshake: self.handshake.clone(),
            discovery: Arc::clone(&self.discovery),
            spanning_tree: Arc::clone(&self.spanning_tree),
            local_id: self.local_id.clone(),
            local_info: self.local_info.clone(),
            local_cipher_key: self.local_cipher_key,
            trusted_peers: RwLock::new(self.trusted_peers.read().unwrap().clone()),
            banned_peers: RwLock::new(self.banned_peers.read().unwrap().clone()),
            running: AtomicBool::new(self.running.load(Ordering::SeqCst)),
            connection_limit: self.connection_limit,
            message_queue: Arc::clone(&self.message_queue),
            kyber: self.kyber.clone(),
            dilithium: self.dilithium.clone(),
            ddos_protection: Mutex::new(DdosProtection::new(100, 60)),
            
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyRotationData {
    new_public_key: Vec<u8>,
    kyber_ciphertext: Vec<u8>,
    verification_nonce: Vec<u8>,
    encrypted_verification: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HandshakeData {
    protocol_version: String,
    node_id: NodeId,
    public_key: Vec<u8>,
    timestamp: u64,
    address: SocketAddr,
    nonce: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HandshakeMessage {
    data: HandshakeData,
    signature: Vec<u8>,
}


// Connection quality metrics
struct ConnectionMetrics {
    first_connected: Instant,
    last_message: Instant,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    failures: u32,
    latency_ms: Option<u32>,
}

struct QueuedMessage {
    node_id: NodeId,
    message: Message,
    priority: u32,
    enqueue_time: Instant,
}

 //Estrutura para DDOS
struct DdosProtection {
    // Mapa de IP para contagem de conexões
    connection_counts: HashMap<std::net::IpAddr, u32>,
    // Timestamp da última limpeza
    last_cleanup: Instant,
    // Limite de conexões por IP
    connection_limit: u32,
    // Período de monitoramento em segundos
    monitoring_period: u64,
}

impl DdosProtection {
    pub fn new(connection_limit: u32, monitoring_period: u64) -> Self {
        Self {
            connection_counts: HashMap::new(),
            last_cleanup: Instant::now(),
            connection_limit,
            monitoring_period,
        }
    }
    
    pub fn should_allow_connection(&mut self, addr: &SocketAddr) -> bool {
        // Limpar contadores antigos
        if self.last_cleanup.elapsed() > Duration::from_secs(self.monitoring_period) {
            self.connection_counts.clear();
            self.last_cleanup = Instant::now();
        }
        
        // Incrementar contador para este IP
        let count = self.connection_counts.entry(addr.ip()).or_insert(0);
        *count += 1;
        
        // Verificar se excedeu o limite
        *count <= self.connection_limit
    }
}

impl Clone for DdosProtection {
    fn clone(&self) -> Self {
        Self {
            connection_counts: self.connection_counts.clone(),
            last_cleanup: self.last_cleanup,
            connection_limit: self.connection_limit,
            monitoring_period: self.monitoring_period,
        }
    }
}

// Enhanced NetworkManager with quantum security
pub struct SecureNetworkManager {
    // Node connections and state
    nodes: Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
    metrics: Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
    
    // Core components
    listener: TcpListener,
    handshake: Handshake,
    discovery: Arc<EnhancedNodeDiscovery>,
    spanning_tree: Arc<RwLock<SpanningTree>>,
    
    // Identity
    local_id: NodeId,
    local_info: NodeInfo,
    
    // Security
    local_cipher_key: [u8; 32],
    trusted_peers: RwLock<HashSet<NodeId>>,
    banned_peers: RwLock<HashSet<NodeId>>,
    
    // State
    running: AtomicBool,
    connection_limit: usize,
    
    // Queue for outgoing messages
    message_queue: Arc<Mutex<Vec<QueuedMessage>>>,
    
    // Crypto
    kyber: Kyber512,
    dilithium: Dilithium5,

    //DDos_protection
    ddos_protection: Mutex<DdosProtection>,
}

impl SecureNetworkManager {
    // Constants
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
    const MAX_RETRY_COUNT: u32 = 3;
    const QUEUE_PROCESS_INTERVAL: Duration = Duration::from_millis(50);
    
    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    // Create new secure network manager
   pub fn new(
        address: &str,
        local_id: String,
        public_key: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(address)?;
        let local_addr = listener.local_addr()?;
        info!("NetworkManager bound to {}", local_addr);
        
        let mut local_cipher_key = [0u8; 32];
        thread_rng().fill_bytes(&mut local_cipher_key);
        
        let kyber = Kyber512::new()?;
        let dilithium = Dilithium5::new()?;
        let handshake = Handshake::new()?;
        
        let local_info = NodeInfo {
            id: local_id.clone(),
            address: local_addr,
            public_key,
            services: HashSet::new(),
            protocol_version: "1.0".to_string(),
        };
        
        let discovery = Arc::new(EnhancedNodeDiscovery::new(local_id.clone()));
        let spanning_tree = Arc::new(RwLock::new(SpanningTree::new(local_id.clone())));
        
        Ok(Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            listener,
            handshake,
            discovery,
            spanning_tree,
            local_id,
            local_info,
            local_cipher_key,
            trusted_peers: RwLock::new(HashSet::new()),
            banned_peers: RwLock::new(HashSet::new()),
            running: AtomicBool::new(false),
            connection_limit: 100,
            message_queue: Arc::new(Mutex::new(Vec::new())),
            kyber,
            dilithium,
            ddos_protection: Mutex::new(DdosProtection::new(100, 60)),
        })
    }
    
    // Start network services
    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err("Network already started".into());
        }
        
        info!("Starting secure network manager on {}", self.listener.local_addr()?);
        
        // Start connection listener
        self.start_listener()?;
        
        // Start message queue processor
        self.start_queue_processor()?;
        
        // Start heartbeat service
        self.start_heartbeat_service()?;
        
        // Load node cache if discovery is configured
        if let Err(e) = self.discovery.load_node_cache() {
            warn!("Failed to load node cache: {}", e);
        }
        
        info!("Network services started successfully");
        Ok(())
    }
    
    // Start connection listener
    fn start_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
    let nodes_clone = Arc::clone(&self.nodes);
    let metrics_clone = Arc::clone(&self.metrics);
    let handshake_clone = self.handshake.clone();
    let discovery_clone = Arc::clone(&self.discovery);
    let spanning_tree_clone = Arc::clone(&self.spanning_tree);
    let listener_addr = self.listener.local_addr()?;
    let listener_clone = self.listener.try_clone()?;
    let local_id_clone = self.local_id.clone();
    let local_info_clone = self.local_info.clone();
    let banned_peers_clone = Arc::new(RwLock::new(self.banned_peers.read().unwrap().clone()));
    let running_value = self.running.load(Ordering::SeqCst);
    let running = Arc::new(AtomicBool::new(running_value));
    let ddos_protection_clone = Arc::new(Mutex::new(self.ddos_protection.lock().unwrap().clone())); 

    std::thread::spawn(move || {
        info!("Listening for connections on {}", listener_addr);
        
        let _ = listener_clone.set_nonblocking(true);
        
        while running.load(Ordering::SeqCst) {
            match listener_clone.accept() {
                Ok((stream, addr)) => {
                    let allow_connection = {
                        let mut ddos_protection = ddos_protection_clone.lock().unwrap();
                        let allowed = ddos_protection.should_allow_connection(&addr);
                        if !allowed {
                            info!("Conexões atuais de {}: {}", addr.ip(), ddos_protection.connection_counts.get(&addr.ip()).unwrap_or(&0));
                        }
                        allowed
                    };
                    
                    if !allow_connection {
                        warn!("Rejected connection from {} due to rate limiting", addr);
                        continue;
                    }

                    let peer_id = format!("peer_{}", addr);
                    let banned = {
                        let banned_peers = banned_peers_clone.read().unwrap();
                        banned_peers.contains(&peer_id)
                    };
                    
                    if banned {
                        warn!("Rejected connection from banned peer: {}", addr);
                        continue;
                    }
                    
                    info!("Accepted connection from {}", addr);
                    
                    let nodes_thread = Arc::clone(&nodes_clone);
                    let metrics_thread = Arc::clone(&metrics_clone);
                    let handshake_thread = handshake_clone.clone();
                    let discovery_thread = Arc::clone(&discovery_clone);
                    let spanning_tree_thread = Arc::clone(&spanning_tree_clone);
                    let local_id_thread = local_id_clone.clone();
                    let local_info_thread = local_info_clone.clone();
                    
                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_inbound_connection(
                            stream,
                            addr,
                            nodes_thread,
                            metrics_thread,
                            handshake_thread,
                            discovery_thread,
                            spanning_tree_thread,
                            &local_id_thread,
                            &local_info_thread,
                        ) {
                            error!("Error handling connection from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    if e.kind() != ErrorKind::WouldBlock {
                        error!("Error accepting connection: {}", e);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        
        info!("Connection listener stopped");
    });
    
    Ok(())
}

    pub fn start_connection_health_check(&self, interval_secs: u64) {
        let nodes = Arc::clone(&self.nodes);
        let metrics = Arc::clone(&self.metrics);
        let discovery = Arc::clone(&self.discovery);
        let spanning_tree = Arc::clone(&self.spanning_tree);

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(interval_secs));

                let mut to_disconnect = Vec::new();

                // Verificar a saúde de cada conexão
                {
                    let connections = nodes.read().unwrap();
                    for (node_id, _) in connections.iter() {
                        if !Self::check_connection_health(node_id, &metrics) {
                            to_disconnect.push(node_id.clone());
                        }
                    }
                }

                // Desconectar nós com problemas
                for node_id in to_disconnect {
                    info!("Disconnecting unhealthy node: {}", node_id);

                    // Marcado como falha para discovery
                    discovery.update_reputation(&node_id, false, None);

                    // Removendo conexão
                    let _ = Self::handle_peer_disconnect(
                        &node_id,
                        &nodes,
                        &metrics,
                        &discovery,
                        &spanning_tree,
                    );
                }
            }
        });
    }

    pub fn update_node_services(&self, node_id: &NodeId, services: HashSet<String>) -> bool {
    let mut nodes = match self.nodes.write() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de escrita para nós: {}", e);
            return false;
        }
    };
    
    if let Some(node) = nodes.get_mut(node_id) {
        node.0.services = services;
        debug!("Serviços atualizados para nó {}: {:?}", node_id, node.0.services);
        true
    } else {
        warn!("Tentativa de atualizar serviços para nó não encontrado: {}", node_id);
        false
    }
}

pub fn update_protocol_version(&self, node_id: &NodeId, version: String) -> bool {
    let mut nodes = match self.nodes.write() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de escrita para nós: {}", e);
            return false;
        }
    };
    
    if let Some(node) = nodes.get_mut(node_id) {
        node.0.protocol_version = version.clone();
        debug!("Versão de protocolo atualizada para nó {}: {}", node_id, version);
        true
    } else {
        warn!("Tentativa de atualizar versão para nó não encontrado: {}", node_id);
        false
    }
}

pub fn get_nodes_with_service(&self, service: &str) -> Vec<NodeInfo> {
    let nodes = match self.nodes.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de leitura para nós: {}", e);
            return Vec::new();
        }
    };
    
    let matching_nodes: Vec<NodeInfo> = nodes.iter()
        .filter(|(_, node)| node.0.services.contains(service))
        .map(|(_, node)| node.0.clone())
        .collect();
    
    info!("Encontrados {} nós oferecendo o serviço '{}'", matching_nodes.len(), service);
    matching_nodes
}

pub fn is_compatible_version(&self, node_id: &NodeId) -> Result<bool, String> {
    // Adicionando dependência semver para uma comparação de versão robusta
    // Caso ainda não tenha, adicione no Cargo.toml:
    // semver = "1.0"
    
    let nodes = match self.nodes.read() {
        Ok(guard) => guard,
        Err(e) => return Err(format!("Falha ao adquirir lock de leitura: {}", e)),
    };
    
    let node = match nodes.get(node_id) {
        Some(n) => n,
        None => return Err(format!("Nó {} não encontrado", node_id)),
    };
    
    // Versão atual da nossa implementação (ex: requisitos mínimos)
    let min_version = match semver::Version::parse("1.0.0") {
        Ok(v) => v,
        Err(e) => return Err(format!("Erro ao analisar versão mínima: {}", e)),
    };
    
    // Analisar versão do nó remoto
    let remote_version = match semver::Version::parse(&node.0.protocol_version) {
        Ok(v) => v,
        Err(e) => return Err(format!("Erro ao analisar versão do nó remoto: {}", e)),
    };
    
    // Verificar compatibilidade (mesma versão principal)
    let compatible = remote_version.major == min_version.major;
    
    if !compatible {
        warn!("Versão incompatível detectada para nó {}: {} (requer {})",
            node_id, node.0.protocol_version, min_version);
    } else {
        debug!("Versão compatível para nó {}: {}", node_id, node.0.protocol_version);
    }
    
    Ok(compatible)
}

pub fn find_nodes_by_version(&self, version_prefix: &str) -> Vec<NodeInfo> {
    let nodes = match self.nodes.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de leitura para nós: {}", e);
            return Vec::new();
        }
    };
    
    let matching_nodes: Vec<NodeInfo> = nodes.iter()
        .filter(|(_, node)| node.0.protocol_version.starts_with(version_prefix))
        .map(|(_, node)| node.0.clone())
        .collect();
    
    info!("Encontrados {} nós com versão de protocolo '{}*'", 
          matching_nodes.len(), version_prefix);
    
    matching_nodes
}


fn check_connection_health(node_id: &NodeId, metrics: &Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>) -> bool {
    let metrics = metrics.read().unwrap();
    if let Some(node_metrics) = metrics.get(node_id) {
        let inactive_time = node_metrics.last_message.elapsed();
        let connection_age = node_metrics.first_connected.elapsed();
        if inactive_time > Duration::from_secs(300) || connection_age > Duration::from_secs(3600) { // 1 hora
            info!("Conexão {} inativa ou muito antiga: {:?}", node_id, connection_age);
            return false;
        }
        if node_metrics.failures > 5 {
            return false;
        }
    }
    true
}

pub fn update_node_info(&self, node_id: &NodeId, updated_info: NodeInfo) -> Result<(), Box<dyn std::error::Error>> {
    // Obter uma trava de escrita para o mapa de nós
    let mut nodes_write = self.nodes.write().unwrap();
    
    // Verificar se o nó existe
    if let Some((_, cipher)) = nodes_write.get(node_id) {
        let cipher_clone = cipher.clone();
        
        // Atualizar a entrada com as novas informações, mantendo o mesmo cipher
        nodes_write.insert(node_id.clone(), (updated_info, cipher_clone));
        
        info!("Updated node info for {}", node_id);
        return Ok(());
    }
    
    // Retornar erro se o nó não for encontrado
    Err(format!("Node {} not found", node_id).into())
}

    
    // Handle inbound connection
    fn handle_inbound_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    nodes: Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
    metrics: Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
    handshake: Handshake,
    discovery: Arc<EnhancedNodeDiscovery>,
    spanning_tree: Arc<RwLock<SpanningTree>>,
    local_id: &NodeId,
    local_info: &NodeInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    // Set timeouts
    stream.set_read_timeout(Some(Self::HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(Self::HANDSHAKE_TIMEOUT))?;
    
    // Read handshake data with size prefix
    let mut size_buffer = [0u8; 4];
    stream.read_exact(&mut size_buffer)?;
    let size = u32::from_be_bytes(size_buffer) as usize;
    
    // Validate size to prevent DoS
    if size > Self::MAX_MESSAGE_SIZE {
        return Err(format!("Handshake message too large: {} bytes", size).into());
    }
    
    // Read handshake data
    let mut handshake_data = vec![0u8; size];
    stream.read_exact(&mut handshake_data)?;
    
    // Create temporary peer info
    let peer_id = format!("peer_{}", addr);
    let mut peer_info = NodeInfo {
    id: peer_id.clone(),
    address: addr,
    public_key: Vec::new(),
    services: HashSet::new(),              
    protocol_version: "1.0".to_string(),   
};
    
    // Perform enhanced handshake
    let (shared_secret, _cipher, response_data) = handshake.perform_enhanced_handshake(
        local_info,
        &peer_info,
        &handshake_data,
    )?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&shared_secret[..32]);
    let enhanced_cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    
    // Send handshake response
    let response_len = response_data.len() as u32;
    stream.write_all(&response_len.to_be_bytes())?;
    stream.write_all(&response_data)?;
    stream.flush()?;
    
    // Read peer identity from handshake
    peer_info = Self::extract_peer_info_from_handshake(&handshake_data)?;
    
    info!("Completed handshake with {}", peer_info.id);
    
    // Update node list with enhanced_cipher
    {
        let mut nodes_write = nodes.write().unwrap();
        nodes_write.insert(peer_info.id.clone(), (peer_info.clone(), enhanced_cipher.clone()));
        
        let mut metrics_write = metrics.write().unwrap();
        metrics_write.insert(peer_info.id.clone(), ConnectionMetrics {
            first_connected: Instant::now(),
            last_message: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            failures: 0,
            latency_ms: None,
        });
    }
    
    // Add to discovery
    discovery.add_node(peer_info.clone(), true);
    
    // Add to spanning tree
    {
        let mut tree = spanning_tree.write().unwrap();
        tree.add_node(peer_info.id.clone(), local_id.clone());
    }
    
    // Start message listener for this peer
    Self::start_peer_listener(
        peer_info.id.clone(),
        stream,
        nodes.clone(),
        metrics.clone(),
        discovery.clone(),
        spanning_tree.clone(),
        local_id.clone(),
    )?;
    
    Ok(())
}
    
    // Extract peer info from handshake data
   
fn extract_peer_info_from_handshake(handshake_data: &[u8]) -> Result<NodeInfo, Box<dyn std::error::Error>> {
    // Desserializar a mensagem de handshake
    let handshake: HandshakeMessage = bincode::deserialize(handshake_data)
        .map_err(|e| format!("Failed to deserialize handshake: {}", e))?;
    
    // Extrair informações do nó
    let node_info = NodeInfo {
    id: handshake.data.node_id.clone(),
    address: handshake.data.address,
    public_key: handshake.data.public_key.clone(),
    protocol_version: "1.0".to_string(),
    services: HashSet::new(), 
};
    
    Ok(node_info)
}
    
    // Start message listener for a peer
    fn start_peer_listener(
    peer_id: NodeId,
    stream: TcpStream,
    nodes: Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
    metrics: Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
    discovery: Arc<EnhancedNodeDiscovery>,
    spanning_tree: Arc<RwLock<SpanningTree>>,
    local_id: NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = stream.try_clone()?;
    
    // Set read timeout
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    
    std::thread::spawn(move || {
        info!("Started message listener for {}", peer_id);
        
        let mut buffer = vec![0u8; 4]; // Size prefix buffer
        
        loop {
            // Read message size
            match stream.read_exact(&mut buffer) {
                Ok(_) => {
                    let size = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                    
                    // Validate message size
                    if size > SecureNetworkManager::MAX_MESSAGE_SIZE {
                        error!("Message from {} too large: {} bytes", peer_id, size);
                        break;
                    }
                    
                    // Read message data
                    let mut message_data = vec![0u8; size];
                    match stream.read_exact(&mut message_data) {
                        Ok(_) => {
                            // Key Rotation Handler
                            let key_rotation_handler = |node_id: &NodeId, payload: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
    info!("Rotacionando chave para nó {}", node_id);
    
    // Criar nova instância Kyber para criptografia pós-quântica
    let kyber = Kyber512::new()?;
    
    // Gerar novo par de chaves
    let (new_local_public_key, new_local_secret_key) = kyber.keypair()?;
    let new_local_public_key_vec = new_local_public_key.into_vec();
    let new_local_secret_key_vec = new_local_secret_key.into_vec();
    
    // Validar chave pública recebida do par
    let remote_public_key: Vec<u8> = bincode::deserialize(payload)
        .map_err(|e| format!("Falha ao desserializar chave pública remota: {}", e))?;
    
    info!("Recebida chave pública remota de tamanho: {} bytes", remote_public_key.len());
    
    // Verificar validade da chave pública
    if remote_public_key.len() < 32 {
        return Err("Chave pública recebida é muito curta para ser válida".into());
    }
    
    // Encapsular um segredo compartilhado usando a nova chave pública remota
    let remote_pk = kyber.public_key_from_bytes(&remote_public_key)?;
    let (shared_secret, ciphertext) = kyber.encapsulate(&remote_pk)?;
    let shared_secret_vec = shared_secret.to_vec();


    
    // Criar dados de verificação para garantir que a chave está funcionando
    let verification_data = format!("verify_{}", uuid::Uuid::new_v4());
    
    // Criar cifra com o segredo compartilhado
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret_vec[..32])
        .map_err(|e| format!("Falha ao criar cifra: {}", e))?;
    
    // Cifrar dados de verificação
    let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let encrypted_verification = cipher.encrypt(&nonce, verification_data.as_bytes())
        .map_err(|e| format!("Falha ao cifrar dados de verificação: {}", e))?;
    
    // Criar objeto de rotação de chave
    let rotation_data = KeyRotationData {
        new_public_key: new_local_public_key_vec,
        kyber_ciphertext: ciphertext.to_vec(),
        verification_nonce: nonce.to_vec(),
        encrypted_verification,
    };
    
    // Serializar dados de rotação
    let new_payload = bincode::serialize(&rotation_data)?;
    
    // Enviar para o nó
    SecureNetworkManager::queue_message_to_peer(
        node_id.clone(),
        Message {
            sender: local_id.clone(),
            message_type: MessageType::KeyRotation,
            payload: new_payload,
        },
        &nodes,
        &metrics,
    );
    
    // Atualizar chaves locais de forma segura
    // Em um sistema real, isso seria armazenado em um cofre de chaves
    info!("Nova chave secreta gerada com comprimento: {} bytes", new_local_secret_key_vec.len());
    info!("Novo segredo compartilhado estabelecido: {} bytes", shared_secret_vec.len());
    
    // Adicionar log de auditoria para segurança
    info!("Rotação de chave completa para nó {} às {}", 
          node_id, 
          chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    
    Ok(())
};

                            // Process message
                            match SecureNetworkManager::process_encrypted_message(
                                &peer_id,
                                &message_data,
                                &nodes,
                                &metrics,
                                &discovery,
                                &spanning_tree,
                                &local_id,
                                Some(&key_rotation_handler),
                            ) {
                                Ok(_) => {
                                    // Update metrics
                                    let mut metrics_write = metrics.write().unwrap();
                                    if let Some(metrics) = metrics_write.get_mut(&peer_id) {
                                        metrics.last_message = Instant::now();
                                        metrics.messages_received += 1;
                                        metrics.bytes_received += size as u64;
                                    }
                                }
                                Err(e) => {
                                    error!("Error processing message from {}: {}", peer_id, e);
                                    // Update failure count
                                    let mut metrics_write = metrics.write().unwrap();
                                    if let Some(metrics) = metrics_write.get_mut(&peer_id) {
                                        metrics.failures += 1;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if e.kind() == ErrorKind::UnexpectedEof {
                                info!("Connection closed by {}", peer_id);
                            } else {
                                error!("Error reading message data from {}: {}", peer_id, e);
                            }
                            break;
                        }
                    }
                }
                Err(e) => {
                    match e.kind() {
                        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                            // Timeout is normal, continue
                            continue;
                        }
                        ErrorKind::UnexpectedEof => {
                            info!("Connection closed by {}", peer_id);
                            break;
                        }
                        _ => {
                            error!("Error reading message size from {}: {}", peer_id, e);
                            break;
                        }
                    }
                }
            }
        }
        
        // Connection cleanup
        let _ = SecureNetworkManager::handle_peer_disconnect(
            &peer_id,
            &nodes,
            &metrics,
            &discovery,
            &spanning_tree,
        );
        
        info!("Message listener for {} stopped", peer_id);
    });
    
    Ok(())
}
   
    // Process encrypted message
    fn process_encrypted_message(
        
        peer_id: &NodeId,
        encrypted_data: &[u8],
        nodes: &Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
        metrics: &Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
        discovery: &Arc<EnhancedNodeDiscovery>,
        spanning_tree: &Arc<RwLock<SpanningTree>>,
        local_id: &NodeId,
        key_rotation_callback: Option<&dyn Fn(&NodeId, &[u8]) -> Result<(), Box<dyn std::error::Error>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Get cipher for this peer
        let nodes_read = nodes.read().unwrap();
        let (_, cipher) = nodes_read.get(peer_id)
            .ok_or_else(|| format!("No connection info for {}", peer_id))?;
        
        // First 12 bytes are nonce
        if encrypted_data.len() <= 12 {
            return Err("Message too short to contain nonce".into());
        }
        
        let nonce = chacha20poly1305::Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        // Decrypt message
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        // Deserialize message
        let message: Message = bincode::deserialize(&plaintext)
            .map_err(|e| format!("Deserialization failed: {}", e))?;

            
// Verificar o remetente
if message.sender != *peer_id {
    return Err(format!("Message sender mismatch: expected {}, got {}", peer_id, message.sender).into());
}

// Verificar o tamanho máximo da mensagem
if message.payload.len() > Self::MAX_MESSAGE_SIZE {
    return Err(format!("Message payload too large: {} bytes", message.payload.len()).into());
}


trace!("Received message type {:?} from {}", message.message_type, peer_id);
        
        
        // Process based on message type
        match message.message_type {
            MessageType::Handshake => {
                // This shouldn't happen after initial handshake
                warn!("Unexpected handshake message from {}", peer_id);
            }
            MessageType::BlockProposal => {
                info!("Received block proposal from {}", peer_id);
                
                // Update reputation and metrics
                discovery.update_reputation(peer_id, true, None);
                
                // Forward to consensus layer (not implemented here)
            }
            MessageType::Vote => {
                debug!("Received vote from {}", peer_id);
                
                // Update reputation
                discovery.update_reputation(peer_id, true, None);
                
                // Forward to consensus layer (not implemented here)
            }
            MessageType::CrossChainRequest => {
                info!("Received cross-chain request from {}", peer_id);
                
                // Forward to bridge manager (not implemented here)
            }
            MessageType::CrossChainResponse => {
                info!("Received cross-chain response from {}", peer_id);
                
                // Forward to bridge manager (not implemented here)
            }
            MessageType::DiscoveryRequest => {
                debug!("Received discovery request from {}", peer_id);
                
                // Find nodes to share with peer
                let nearby_nodes = discovery.find_closest_nodes(peer_id, 20);
                
                // Create response
                let response_payload = bincode::serialize(&nearby_nodes)
                    .map_err(|e| format!("Failed to serialize node list: {}", e))?;
                
                let response = Message {
                    sender: local_id.clone(),
                    message_type: MessageType::DiscoveryResponse,
                    payload: response_payload,
                };
                
                // Queue response
                Self::queue_message_to_peer(
                    peer_id.clone(),
                    response,
                    nodes,
                    metrics,
                );
                
                // Update discovery metrics
                discovery.update_reputation(peer_id, true, None);
            }
            MessageType::DiscoveryResponse => {
                debug!("Received discovery response from {}", peer_id);
                
                // Deserialize node list
                let nodes_list: Vec<NodeInfo> = bincode::deserialize(&message.payload)
                    .map_err(|e| format!("Failed to deserialize node list: {}", e))?;
                
                // Process discovery response
                let added = discovery.process_discovery_response(peer_id, nodes_list);
                debug!("Added {} new nodes from discovery response", added);
                
                // Update spanning tree with new nodes
                if added > 0 {
                    let mut tree = spanning_tree.write().unwrap();
                    tree.optimize();
                }
            }
            MessageType::Heartbeat => {
                trace!("Received heartbeat from {}", peer_id);
                
                // Measure latency if timestamp included
                if message.payload.len() >= 8 {
                    let timestamp_bytes = &message.payload[0..8];
                    let timestamp = u64::from_be_bytes([
                        timestamp_bytes[0], timestamp_bytes[1], timestamp_bytes[2], timestamp_bytes[3],
                        timestamp_bytes[4], timestamp_bytes[5], timestamp_bytes[6], timestamp_bytes[7],
                    ]);
                    
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    
                    let latency = (now - timestamp) as u32;
                    
                    // Update metrics
                    let mut metrics_write = metrics.write().unwrap();
                    if let Some(metrics) = metrics_write.get_mut(peer_id) {
                        metrics.latency_ms = Some(latency);
                    }
                    
                    // Update discovery with latency information
                    discovery.update_reputation(peer_id, true, Some(latency));
                }
                
                // Send heartbeat response
                let response = Message {
                    sender: local_id.clone(),
                    message_type: MessageType::HeartbeatResponse,
                    payload: message.payload,  // Echo back the same payload
                };
                
                Self::queue_message_to_peer(
                    peer_id.clone(),
                    response,
                    nodes,
                    metrics,
                );
            }


            MessageType::KeyRotation => {
        info!("Received key rotation from {}", peer_id);
        
        // Chamar a callback se fornecida
            if let Some(callback) = key_rotation_callback {
                if let Err(e) = callback(peer_id, &message.payload) {
                    warn!("Key rotation processing failed: {}", e);
            }
        }
},

            MessageType::HeartbeatResponse => {
                trace!("Received heartbeat response from {}", peer_id);
                
                // Calculate round trip time if possible
                if message.payload.len() >= 8 {
                    let timestamp_bytes = &message.payload[0..8];
                    let sent_timestamp = u64::from_be_bytes([
                        timestamp_bytes[0], timestamp_bytes[1], timestamp_bytes[2], timestamp_bytes[3],
                        timestamp_bytes[4], timestamp_bytes[5], timestamp_bytes[6], timestamp_bytes[7],
                    ]);
                    
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    
                    let rtt = (now - sent_timestamp) as u32;
                    
                    // Update metrics
                    let mut metrics_write = metrics.write().unwrap();
                    if let Some(metrics) = metrics_write.get_mut(peer_id) {
                        metrics.latency_ms = Some(rtt / 2); // Estimate one-way latency
                    }
                    
                    // Update discovery with latency information
                    discovery.update_reputation(peer_id, true, Some(rtt / 2));
                    
                    trace!("RTT to {}: {}ms", peer_id, rtt);
                }
            }
        }
        
        Ok(())
    }

    fn get_message_priority(message_type: &MessageType) -> u32 {
    match message_type {
        MessageType::Heartbeat | MessageType::HeartbeatResponse => 0, // Baixa prioridade
        MessageType::DiscoveryRequest | MessageType::DiscoveryResponse => 1,
        MessageType::BlockProposal | MessageType::Vote => 10, // Alta prioridade (consenso)
        MessageType::CrossChainRequest | MessageType::CrossChainResponse => 8,
        MessageType::KeyRotation => 9,
        _ => 5, // Prioridade média para outros tipos
    }
}
    
    // Queue message to peer for sending
    fn queue_message_to_peer(
    peer_id: NodeId,
    message: Message,
    nodes: &Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
    metrics: &Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
) {
    let serialized = match bincode::serialize(&message) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to serialize message to {}: {}", peer_id, e);
            return;
        }
    };
    let compressed = Self::compress_message(&serialized).unwrap_or_else(|e| {
        warn!("Compression failed: {}, sending uncompressed", e);
        serialized.clone()
    });
    let was_compressed = compressed.len() < serialized.len();
    if was_compressed {
        trace!("Message to {} compressed from {} to {} bytes", peer_id, serialized.len(), compressed.len());
    }

    let nodes_read = match nodes.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire read lock: {}", e);
            return;
        }
    };
    let (peer_info, cipher) = match nodes_read.get(&peer_id) {
        Some(info) => info,
        None => {
            error!("No connection info for {}", peer_id);
            return;
        }
    };

    let nonce = ChaCha20Poly1305::generate_nonce(&mut thread_rng());
    let ciphertext = match cipher.encrypt(&nonce, compressed.as_slice()) {
        Ok(data) => data,
        Err(e) => {
            error!("Encryption failed for message to {}: {}", peer_id, e);
            return;
        }
    };

    let mut encrypted_message = Vec::with_capacity(12 + ciphertext.len());
    encrypted_message.extend_from_slice(nonce.as_slice());
    encrypted_message.extend_from_slice(&ciphertext);

    match TcpStream::connect_timeout(&peer_info.address, Duration::from_secs(5)) {
        Ok(mut stream) => {
            if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
                error!("Failed to set write timeout for {}: {}", peer_id, e);
                return;
            }
            let size = encrypted_message.len() as u32;
            if let Err(e) = stream.write_all(&size.to_be_bytes()) {
                error!("Failed to send message size to {}: {}", peer_id, e);
                return;
            }
            if let Err(e) = stream.write_all(&encrypted_message) {
                error!("Failed to send message to {}: {}", peer_id, e);
                return;
            }
            if let Err(e) = stream.flush() {
                error!("Failed to flush message to {}: {}", peer_id, e);
                return;
            }
            let mut metrics_write = match metrics.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire metrics write lock: {}", e);
                    return;
                }
            };
            if let Some(metrics) = metrics_write.get_mut(&peer_id) {
                metrics.messages_sent += 1;
                metrics.bytes_sent += (4 + encrypted_message.len()) as u64;
            }
            trace!("Sent message type {:?} to {}", message.message_type, peer_id);
        }
        Err(e) => error!("Failed to connect to {} for sending: {}", peer_id, e),
    }
}
    
    // Handle peer disconnection
    fn handle_peer_disconnect(
        peer_id: &NodeId,
        nodes: &Arc<RwLock<HashMap<NodeId, (NodeInfo, ChaCha20Poly1305)>>>,
        metrics: &Arc<RwLock<HashMap<NodeId, ConnectionMetrics>>>,
        discovery: &Arc<EnhancedNodeDiscovery>,
        spanning_tree: &Arc<RwLock<SpanningTree>>,
    ) {
        // Remove from nodes map
        {
            let mut nodes_write = match nodes.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire nodes write lock: {}", e);
                    return;
                }
            };
            
            nodes_write.remove(peer_id);
        }
        
        // Update metrics
        {
            let mut metrics_write = match metrics.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire metrics write lock: {}", e);
                    return;
                }
            };
            
            metrics_write.remove(peer_id);
        }
        
        // Update discovery
        discovery.update_reputation(peer_id, false, None);
        
        // Update spanning tree
        {
            let mut tree = match spanning_tree.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire spanning tree write lock: {}", e);
                    return;
                }
            };
            
            if tree.remove_node(peer_id) {
                // Re-optimize tree after node removal
                tree.optimize();
            }
        }
        
        info!("Peer {} disconnected and removed from network", peer_id);
    }
    
    // Start message queue processor
    fn start_queue_processor(&self) -> Result<(), Box<dyn std::error::Error>> {
    let queue = Arc::clone(&self.message_queue);
    let nodes = Arc::clone(&self.nodes);
    let metrics = Arc::clone(&self.metrics);
    let running = Arc::new(AtomicBool::new(self.running.load(Ordering::SeqCst)));

    std::thread::spawn(move || {
        info!("Message queue processor started");
        
        while running.load(Ordering::SeqCst) {
            // Obter mensagens da fila
            let messages = {
                let mut queue = queue.lock().unwrap();
                
                // Ordenar por prioridade (maior primeiro) e depois por tempo (mais antigo primeiro)
                queue.sort_by(|a, b| {
                    match b.priority.cmp(&a.priority) {
                        std::cmp::Ordering::Equal => a.enqueue_time.cmp(&b.enqueue_time),
                        other => other,
                    }
                });
                
                // Limitar quantidade de mensagens processadas por ciclo
                let max_batch = 20;
                let count = std::cmp::min(max_batch, queue.len());
                let messages = queue.drain(0..count).collect::<Vec<_>>();
                
                messages
            };
            
            // Processar mensagens em ordem de prioridade
            for queued in messages {
                Self::queue_message_to_peer(
                    queued.node_id,
                    queued.message,
                    &nodes,
                    &metrics,
                );
            }
            
            // Sleep briefly
            std::thread::sleep(Self::QUEUE_PROCESS_INTERVAL);
        }
        
        info!("Message queue processor stopped");
    });
    
    Ok(())
}

    // Adicione esta função utilitária em network.rs
fn compress_message(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use flate2::{Compress, Compression};
    let mut compressor = Compress::new(Compression::default(), true);
    let mut compressed = Vec::with_capacity(data.len());
    compressor.compress_vec(data, &mut compressed, flate2::FlushCompress::Finish)?;
    if compressed.len() < data.len() {
        Ok(compressed)
    } else {
        Ok(data.to_vec())
    }
}

// E a descompressão:
fn decompress_message(data: &[u8], original_was_compressed: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !original_was_compressed {
        return Ok(data.to_vec());
    }
    use flate2::{Decompress, FlushDecompress};
    let mut decompressor = Decompress::new(true);
    let mut decompressed = Vec::with_capacity(data.len() * 2);
    decompressor.decompress_vec(data, &mut decompressed, FlushDecompress::Finish)?;
    Ok(decompressed)
}
    
    // Start heartbeat service
    fn start_heartbeat_service(&self) -> Result<(), Box<dyn std::error::Error>> {
        let nodes = Arc::clone(&self.nodes);
        let metrics = Arc::clone(&self.metrics);
        let local_id = self.local_id.clone();
        let running = self.running.load(Ordering::SeqCst);
        
        std::thread::spawn(move || {
            info!("Heartbeat service started");
            
            while running {
                // Sleep until next heartbeat
                std::thread::sleep(Self::HEARTBEAT_INTERVAL);
                
                // Get current timestamp for measuring latency
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                
                let timestamp_bytes = now.to_be_bytes().to_vec();
                
                // Create heartbeat message
                let heartbeat = Message {
                    sender: local_id.clone(),
                    message_type: MessageType::Heartbeat,
                    payload: timestamp_bytes,
                };
                
                // Get connected peers
                let connected_peers: Vec<NodeId> = {
                    let nodes_read = match nodes.read() {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("Failed to acquire nodes read lock: {}", e);
                            continue;
                        }
                    };
                    
                    nodes_read.keys().cloned().collect()
                };
                
                // Send heartbeat to each peer
                for peer_id in &connected_peers {
                    Self::queue_message_to_peer(
                    peer_id.clone(),
                        heartbeat.clone(),
                        &nodes,
                        &metrics,
                    );
                }
                
                trace!("Sent heartbeat to {} peers", connected_peers.len());
            }
            
            info!("Heartbeat service stopped");
        });
        
        Ok(())
    }
    
    // Connect to a remote node
    pub fn connect_to_node(&self, address: &str) -> Result<NodeId, Box<dyn std::error::Error>> {
    info!("Connecting to node at {}", address);

    // Check connection limit
    {
        let nodes_read = self.nodes.read().unwrap();
        if nodes_read.len() >= self.connection_limit {
            return Err("Connection limit reached".into());
        }
    }

    // Parse address
    let socket_addr: SocketAddr = address.parse()?;

    // Check if already connected
    let temp_id = format!("temp_{}", socket_addr);
    {
        let nodes_read = self.nodes.read().unwrap();
        for (_, (info, _)) in nodes_read.iter() {
            if info.address == socket_addr {
                return Err(format!("Already connected to {}", address).into());
            }
        }
    }

    // Connect with retries
    let mut stream = None;
    for attempt in 0..Self::MAX_RETRY_COUNT {
        info!("Tentativa de conexão {} de {} para {}", attempt + 1, Self::MAX_RETRY_COUNT, address);
        match TcpStream::connect_timeout(&socket_addr, Self::CONNECTION_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                warn!("Falha na tentativa {}: {}", attempt + 1, e);
                if attempt + 1 == Self::MAX_RETRY_COUNT {
                    return Err(format!("Failed to connect after {} attempts: {}", Self::MAX_RETRY_COUNT, e).into());
                }
                // Backoff simples: espera aumenta linearmente (100ms, 200ms, 300ms)
                let sleep_time = Duration::from_millis(100 * (attempt + 1) as u64);
                info!("Aguardando {}ms antes da próxima tentativa", sleep_time.as_millis());
                std::thread::sleep(sleep_time);
            }
        }
    }

    let stream = stream.ok_or("Failed to establish connection after retries")?;

    // Set timeouts
    stream.set_read_timeout(Some(Self::HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(Self::HANDSHAKE_TIMEOUT))?;

    // Create handshake data
    let handshake_data = self.create_handshake_data()?;

    // Send handshake with size prefix
    let size = handshake_data.len() as u32;
    let mut stream_clone = stream.try_clone()?;
    stream_clone.write_all(&size.to_be_bytes())?;
    stream_clone.write_all(&handshake_data)?;
    stream_clone.flush()?;

    // Read response size
    let mut size_buffer = [0u8; 4];
    stream_clone.read_exact(&mut size_buffer)?;
    let response_size = u32::from_be_bytes(size_buffer) as usize;

    // Validate response size
    if response_size > Self::MAX_MESSAGE_SIZE {
        return Err(format!("Response too large: {} bytes", response_size).into());
    }

    // Read response
    let mut response_data = vec![0u8; response_size];
    stream_clone.read_exact(&mut response_data)?;

    // Create temporary remote info
    let remote_info = NodeInfo {
        id: temp_id.clone(),
        address: socket_addr,
        public_key: Vec::new(),
        protocol_version: "1.0".to_string(),
        services: HashSet::new(),
    };

    // Process handshake response
    let (shared_secret, cipher, _) = self.handshake.perform_enhanced_handshake(&self.local_info, &remote_info, &response_data)?;
    info!("Shared secret established: {:?}", shared_secret);

    // Extract remote node ID from response
    let peer_info = Self::extract_peer_info_from_handshake(&response_data)?;
    let peer_id = peer_info.id.clone();

    // Update node list
    {
        let mut nodes_write = self.nodes.write().unwrap();
        nodes_write.insert(peer_id.clone(), (peer_info.clone(), cipher.clone()));

        let mut metrics_write = self.metrics.write().unwrap();
        metrics_write.insert(peer_id.clone(), ConnectionMetrics {
            first_connected: Instant::now(),
            last_message: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            failures: 0,
            latency_ms: None,
        });
    }

    // Add to discovery
    self.discovery.add_node(peer_info.clone(), true);

    // Add to spanning tree
    {
        let mut tree = self.spanning_tree.write().unwrap();
        tree.add_node(peer_id.clone(), self.local_id.clone());
    }

    // Start message listener
    Self::start_peer_listener(
        peer_id.clone(),
        stream,
        Arc::clone(&self.nodes),
        Arc::clone(&self.metrics),
        Arc::clone(&self.discovery),
        Arc::clone(&self.spanning_tree),
        self.local_id.clone(),
    )?;

    info!("Successfully connected to node {} at {}", peer_id, address);
    Ok(peer_id)
}
    
    // Create handshake data
    fn create_handshake_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Gerar nonce aleatório
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    
    // Obter timestamp atual
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    // Criar dados do handshake
    let handshake_data = HandshakeData {
        protocol_version: "1.0.0".to_string(),
        node_id: self.local_id.clone(),
        public_key: self.local_info.public_key.clone(),
        timestamp,
        address: self.listener.local_addr()?,
        nonce,
    };
    
    // Criar buffer para assinar
    let mut sign_buffer = Vec::new();
    sign_buffer.extend_from_slice(handshake_data.node_id.as_bytes());
    sign_buffer.extend_from_slice(&handshake_data.public_key);
    sign_buffer.extend_from_slice(&nonce);
    sign_buffer.extend_from_slice(&timestamp.to_be_bytes());
    
    // Gerar um par de chaves temporário para assinatura
    let (_, priv_key) = self.dilithium.keypair()?;
    
    // Assinar com Dilithium
    let signature = self.dilithium.sign(&sign_buffer, &priv_key)?;
    
    // Criar mensagem completa
    let handshake_message = HandshakeMessage {
        data: handshake_data,
        signature,
    };
    
    // Serializar
    let serialized = bincode::serialize(&handshake_message)?;
    
    Ok(serialized)
}
    
    // Send message to a specific node
    pub fn send_message(&self, node_id: &NodeId, message: Message) -> Result<(), Box<dyn std::error::Error>> {
    // Check if connected to node
    {
        let nodes_read = self.nodes.read().unwrap();
        if !nodes_read.contains_key(node_id) {
            return Err(format!("Not connected to node {}", node_id).into());
        }
    }
    
    // Obter prioridade antes de mover a mensagem
    let priority = Self::get_message_priority(&message.message_type);
    
    // Queue message with normal priority
    let mut queue = self.message_queue.lock().unwrap();
    queue.push(QueuedMessage {
        node_id: node_id.clone(),
        message,  // Aqui a mensagem é movida
        priority,
        enqueue_time: Instant::now(),
    });
    
    Ok(())
}
    
    // Send high priority message
    pub fn send_priority_message(&self, node_id: &NodeId, message: Message) -> Result<(), Box<dyn std::error::Error>> {
    // Check if connected to node
    {
        let nodes_read = self.nodes.read().unwrap();
        if !nodes_read.contains_key(node_id) {
            return Err(format!("Not connected to node {}", node_id).into());
        }
    }
    
    // Queue message with high priority
    let mut queue = self.message_queue.lock().unwrap();
    queue.push(QueuedMessage {
        node_id: node_id.clone(),
        message,
        priority: 10, // High priority override
        enqueue_time: Instant::now(),
    });
    
    Ok(())
}
    
    // Broadcast message to all connected nodes

pub fn broadcast_message(&self, message: Message) -> Result<usize, Box<dyn std::error::Error>> {
    // Get connected peers
    let peers: Vec<NodeId> = {
        let nodes_read = self.nodes.read().unwrap();
        nodes_read.keys().cloned().collect()
    };
    
    if peers.is_empty() {
        return Ok(0);
    }
    
    // Determine which peers to forward to using spanning tree
    let mut forward_count = 0;
    let message_id = format!("msg_{}", rand::random::<u64>());
    let priority = Self::get_message_priority(&message.message_type);
    
    let mut queue = self.message_queue.lock().unwrap();
    let now = Instant::now();
    
    for peer_id in peers {  // peer_id agora está no escopo correto do loop
        // Check if we should forward to this peer
        let mut tree = self.spanning_tree.write().unwrap();
        if tree.should_forward(&message_id, &self.local_id, &peer_id) {
            // Queue message with determined priority
            queue.push(QueuedMessage {
                node_id: peer_id.clone(),  // Usando peer_id do loop
                message: message.clone(),
                priority,              // Já declarado acima
                enqueue_time: now,     // Já declarado acima
            });
            forward_count += 1;
        }
    }
    
    Ok(forward_count)
}

     pub fn propagate_cross_chain_message(&self, message: CrossChainMessage) -> Result<(), String> {
    // Serializar a mensagem
    let payload = bincode::serialize(&message)
        .map_err(|e| format!("Failed to serialize cross-chain message: {}", e))?;
    
    // Criar mensagem P2P
    let p2p_message = Message {
        sender: self.local_id.clone(),
        message_type: MessageType::CrossChainRequest,
        payload,
    };
    
    // Broadcast para a rede
    self.broadcast_message(p2p_message)
        .map(|_| ())
        .map_err(|e| format!("Failed to broadcast cross-chain message: {}", e.to_string()))
}
    
    // Get metrics for a node
    pub fn get_node_metrics(&self, node_id: &NodeId) -> Option<(u64, u64, Option<u32>)> {
        let metrics_read = self.metrics.read().unwrap();
        
        metrics_read.get(node_id).map(|metrics| {
            (metrics.messages_sent, metrics.messages_received, metrics.latency_ms)
        })
    }
    
    // Get all connected nodes
    pub fn get_connected_nodes(&self) -> Vec<NodeInfo> {
        let nodes_read = self.nodes.read().unwrap();
        
        nodes_read.values()
            .map(|(info, _)| info.clone())
            .collect()
    }
    
    // Get node connection count
    pub fn get_connection_count(&self) -> usize {
        let nodes_read = self.nodes.read().unwrap();
        nodes_read.len()
    }
    
    // Stop network
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Err("Network already stopped".into());
        }
        
        info!("Stopping network services");
        
        // Save discovery node cache
        if let Err(e) = self.discovery.save_node_cache() {
            warn!("Failed to save node cache: {}", e);
        }
        
        // Let threads gracefully shut down
        std::thread::sleep(Duration::from_millis(100));
        
        info!("Network services stopped");
        Ok(())
    }
}