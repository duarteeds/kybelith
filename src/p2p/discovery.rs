use std::collections::{HashMap, HashSet, BinaryHeap};
use std::sync::{Arc, Mutex, RwLock};
use log::{info, warn, debug};
use rand::Rng;
use crate::p2p::types::{NodeId, NodeInfo};
use crate::crypto::hash::quantum_resistant_hash;
use crate::p2p::Message;
use crate::p2p::MessageType;
use crate::p2p::network::SecureNetworkManager;
use std::cmp::Ordering;
use std::time::{Duration, Instant};
use std::sync::atomic::AtomicBool;

impl Clone for EnhancedNodeDiscovery {
    fn clone(&self) -> Self {
        Self {
            nodes: RwLock::new(self.nodes.read().unwrap().clone()),
            buckets: RwLock::new(self.buckets.read().unwrap().clone()),
            local_id: self.local_id.clone(),
            last_cleanup: Mutex::new(*self.last_cleanup.lock().unwrap()),
            trusted_seeds: RwLock::new(self.trusted_seeds.read().unwrap().clone()),
            connection_verifier: None, // Não é possível clonar um Box<dyn Fn>
            node_cache_file: self.node_cache_file.clone(),
            discovery_active: AtomicBool::new(self.discovery_active.load(std::sync::atomic::Ordering::Relaxed)),
            banned_peers: RwLock::new(self.banned_peers.read().unwrap().clone()),
        }
    }
}

// Node with additional metadata for better discovery
#[derive(Clone)]
struct DiscoveryNode {
    node_info: NodeInfo,
    last_seen: Instant,
    reputation: f32,               // 0.0 to 1.0
    successful_connections: u32,
    failed_connections: u32,
    latency_ms: Option<u32>,       // Network latency
    verified: bool,                // Signature verified
    services: HashSet<String>,     // Services offered by this node
    protocol_version: String,      // Protocol version
}

// Node for priority queue based on score
#[derive(Eq)]
struct ScoredNode {
    node_id: NodeId,
    score: u32,
}

impl PartialEq for ScoredNode {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl PartialOrd for ScoredNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.cmp(&other.score)
    }
}

// Enhanced NodeDiscovery structure

pub struct EnhancedNodeDiscovery {
    nodes: RwLock<HashMap<NodeId, DiscoveryNode>>,
    buckets: RwLock<Vec<HashSet<NodeId>>>,  // Kademlia buckets
    local_id: NodeId,
    last_cleanup: Mutex<Instant>,
    trusted_seeds: RwLock<HashSet<NodeId>>, // Known trustworthy nodes
    connection_verifier: Option<Box<dyn Fn(&NodeInfo) -> bool + Send + Sync>>,
    node_cache_file: Option<String>,       // Path to persistent cache
    discovery_active: AtomicBool,          // Flag for active discovery
    banned_peers: RwLock<HashSet<NodeId>>,
}

impl EnhancedNodeDiscovery {
    const BUCKET_COUNT: usize = 256;       // Number of Kademlia buckets (8 bits)
    const MAX_BUCKET_SIZE: usize = 20;     // Maximum nodes per bucket
    const MAX_NODES: usize = 1000;         // Maximum total nodes
    const NODE_TIMEOUT: Duration = Duration::from_secs(3600 * 24); // 24 hours
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);  // 1 hour
    
    pub fn new(local_id: NodeId) -> Self {
        // Initialize buckets
        let mut buckets = Vec::with_capacity(Self::BUCKET_COUNT);
        for _ in 0..Self::BUCKET_COUNT {
            buckets.push(HashSet::new());
        }
        
        Self {
            nodes: RwLock::new(HashMap::new()),
            buckets: RwLock::new(buckets),
            local_id,
            last_cleanup: Mutex::new(Instant::now()),
            trusted_seeds: RwLock::new(HashSet::new()),
            connection_verifier: None,
            node_cache_file: None,
            discovery_active: AtomicBool::new(false),
            banned_peers: RwLock::new(HashSet::new()),
        }
    }
    
    // Set persistent cache file
    pub fn with_cache_file(mut self, path: &str) -> Self {
        self.node_cache_file = Some(path.to_string());
        self
    }
    
    // Add trusted seed nodes
    pub fn with_seeds(self, seeds: Vec<NodeId>) -> Self {
    {
        let mut trusted = self.trusted_seeds.write().unwrap();
        for seed in seeds {
            trusted.insert(seed);
        }
    } // Este escopo garante que o lock seja liberado
    self
}
    
    // Set connection verifier
    pub fn with_verifier<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&NodeInfo) -> bool + Send + Sync + 'static,
    {
        self.connection_verifier = Some(Box::new(verifier));
        self
    }
    
    // Calculate bucket index for a node ID
    fn calculate_bucket_index(&self, node_id: &NodeId) -> usize {
        // Hash the node ID for better distribution
        let node_hash = quantum_resistant_hash(node_id.as_bytes());
        
        // XOR with local ID and find first bit where they differ
        let local_hash = quantum_resistant_hash(self.local_id.as_bytes());
        
        // Find first differing byte
        for (i, (a, b)) in node_hash.iter().zip(local_hash.iter()).enumerate() {
            if a != b {
                // Find first differing bit in this byte
                let xor = a ^ b;
                for bit in 0..8 {
                    if xor & (1 << bit) != 0 {
                        return i * 8 + bit;
                    }
                }
            }
        }
        
        // Default to last bucket if no difference (shouldn't happen with good hashes)
        Self::BUCKET_COUNT - 1
    }

    /// Detectar e banir peers que mostram comportamento suspeito
pub fn detect_malicious_peers(&self) -> Vec<NodeId> {
    let mut suspicious_peers = Vec::new();
    let nodes = self.nodes.read().unwrap();
    
    for (node_id, node) in nodes.iter() {
        // Critérios para detecção:
        // 1. Alta taxa de falhas
        let failure_rate = if node.successful_connections + node.failed_connections > 0 {
            node.failed_connections as f32 / (node.successful_connections + node.failed_connections) as f32
        } else {
            0.0
        };
        
        // 2. Reputação muito baixa
        let low_reputation = node.reputation < 0.1;
        
        // 3. Comportamento anômalo (muitas mensagens em curto período)
        let anomalous_behavior = false; // Implemente lógica real aqui
        
        if (failure_rate > 0.8 && node.failed_connections > 5) || 
           (low_reputation && node.failed_connections > 3) ||
           anomalous_behavior {
            suspicious_peers.push(node_id.clone());
        }
    }
    
    suspicious_peers
}

/// Banir peers maliciosos
pub fn ban_peers(&self, peer_ids: &[NodeId]) -> usize {
    let mut banned_count = 0;
    let mut banned_peers = self.banned_peers.write().unwrap();
    
    for peer_id in peer_ids {
        if !banned_peers.contains(peer_id) {
            banned_peers.insert(peer_id.clone());
            info!("Banned peer {} for suspicious behavior", peer_id);
            banned_count += 1;
        }
    }
    
    banned_count
}
    
    // Add a new node to discovery
    pub fn add_node(&self, node_info: NodeInfo, verified: bool) -> bool {
        // Don't add ourselves
        if node_info.id == self.local_id {
            return false;
        }
        
        // Verify node if callback is set
        if let Some(verifier) = &self.connection_verifier {
            if !verifier(&node_info) {
                warn!("Node {} failed verification", node_info.id);
                return false;
            }
        }
        
        // Create discovery node
        let discovery_node = DiscoveryNode {
            node_info: node_info.clone(),
            last_seen: Instant::now(),
            reputation: if verified { 0.7 } else { 0.5 },
            successful_connections: 0,
            failed_connections: 0,
            latency_ms: None,
            verified,
            services: HashSet::new(),
            protocol_version: "1.0".to_string(),
        };
        
        // Calculate bucket index
        let bucket_index = self.calculate_bucket_index(&node_info.id);
        
        // Add to nodes map
        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(node_info.id.clone(), discovery_node.clone());
        }
        
        // Add to appropriate bucket
        {
            let mut buckets = self.buckets.write().unwrap();
            let bucket = &mut buckets[bucket_index % Self::BUCKET_COUNT];
            
            // If bucket is full, try to evict a low-reputation node
            if bucket.len() >= Self::MAX_BUCKET_SIZE {
                let mut lowest_rep = 1.0;
                let mut lowest_id = None;
                
                let nodes = self.nodes.read().unwrap();
                for id in bucket.iter() {
                    if let Some(node) = nodes.get(id) {
                        if node.reputation < lowest_rep {
                            lowest_rep = node.reputation;
                            lowest_id = Some(id.clone());
                        }
                    }
                }
                
                // Evict lowest reputation node if new node is better
                if let Some(id) = lowest_id {
                    if lowest_rep < discovery_node.reputation {
                        bucket.remove(&id);
                        bucket.insert(node_info.id.clone());
                        debug!("Evicted node {} with rep {:.2} for new node {} with rep {:.2}", 
                              id, lowest_rep, node_info.id, discovery_node.reputation);
                        return true;
                    } else {
                        debug!("Rejected node {} because bucket {} is full", node_info.id, bucket_index);
                        return false;
                    }
                }
            } else {
                bucket.insert(node_info.id.clone());
            }
        }
        
        // Trigger cleanup if we have too many nodes
        {
            let nodes = self.nodes.read().unwrap();
            if nodes.len() > Self::MAX_NODES {
                self.cleanup_nodes();
            }
        }
        
        true
    }
    
    // Update node's reputation based on interactions
    pub fn update_reputation(&self, node_id: &NodeId, success: bool, latency_ms: Option<u32>) {
        let mut nodes = self.nodes.write().unwrap();
        
        if let Some(node) = nodes.get_mut(node_id) {
            // Update last seen
            node.last_seen = Instant::now();
            
            // Update connection success/failure count
            if success {
                node.successful_connections += 1;
            } else {
                node.failed_connections += 1;
            }
            
            // Update latency if provided
            if let Some(latency) = latency_ms {
                node.latency_ms = Some(latency);
            }
            
            // Update reputation score with decay
            // Success counts more for newer nodes, reliability matters more for established nodes
            let conn_ratio = if node.successful_connections + node.failed_connections > 0 {
                node.successful_connections as f32 / 
                (node.successful_connections + node.failed_connections) as f32
            } else {
                0.5
            };
            
            // Exponential decay - recent events matter more
            node.reputation = node.reputation * 0.8 + (if success { 0.2 } else { -0.2 });
            
            // Clamp to valid range
            node.reputation = node.reputation.clamp(0.01, 0.99);
            
            // Trusted seeds get reputation boost
            let trusted = self.trusted_seeds.read().unwrap();
            if trusted.contains(node_id) {
                node.reputation = node.reputation.max(0.7);
            }
            
            debug!("Updated node {} reputation to {:.2} (success: {}, ratio: {:.2})",
                  node_id, node.reputation, success, conn_ratio);
        }
    }
    
    // Find closest nodes to target ID
    pub fn find_closest_nodes(&self, target_id: &NodeId, max_nodes: usize) -> Vec<NodeInfo> {
        // Create a priority queue of nodes by distance
        let mut scored_nodes = BinaryHeap::new();
        let target_bucket = self.calculate_bucket_index(target_id);
        
        // First try to fill from the target bucket
        let nodes_read = self.nodes.read().unwrap();
        let buckets_read = self.buckets.read().unwrap();
        
        // Initialize with nodes from the target bucket
        if target_bucket < Self::BUCKET_COUNT {
            for node_id in &buckets_read[target_bucket] {
                if let Some(node) = nodes_read.get(node_id) {
                    // Skip nodes with very low reputation
                    if node.reputation < 0.2 {
                        continue;
                    }
                    
                    // Calculate node score (lower is better)
                    // We combine XOR distance with reputation
                    let distance = self.calculate_xor_distance(node_id, target_id);
                    
                    // Distance is primary, reputation is secondary
                    // Adjust score so lower values are better (for min-heap)
                    let score = distance;
                    
                    scored_nodes.push(ScoredNode {
                        node_id: node_id.clone(),
                        score,
                    });
                }
            }
        }
        
        // If we don't have enough nodes, try adjacent buckets
        if scored_nodes.len() < max_nodes {
            // Try buckets at increasing distance
            for distance in 1..Self::BUCKET_COUNT {
                // Try bucket before and after target
                let buckets_to_check = [
                    target_bucket.saturating_sub(distance),
                    (target_bucket + distance) % Self::BUCKET_COUNT
                ];
                
                for &bucket_idx in &buckets_to_check {
                    if bucket_idx >= Self::BUCKET_COUNT {
                        continue;
                    }
                    
                    for node_id in &buckets_read[bucket_idx] {
                        if let Some(node) = nodes_read.get(node_id) {
                            // Skip nodes with very low reputation
                            if node.reputation < 0.2 {
                                continue;
                            }
                            
                            let score = self.calculate_xor_distance(node_id, target_id);
                            
                            scored_nodes.push(ScoredNode {
                                node_id: node_id.clone(),
                                score,
                            });
                        }
                    }
                    
                    // Check if we have enough nodes now
                    if scored_nodes.len() >= max_nodes * 2 {
                        break;
                    }
                }
                
                // Check if we have enough nodes now
                if scored_nodes.len() >= max_nodes * 2 {
                    break;
                }
            }
        }
        
        // Convert to vector and return top entries
        let mut result = Vec::with_capacity(max_nodes);
        
        while let Some(ScoredNode { node_id, .. }) = scored_nodes.pop() {
            if let Some(node) = nodes_read.get(&node_id) {
                result.push(node.node_info.clone());
                
                if result.len() >= max_nodes {
                    break;
                }
            }
        }
        
        result
    }
    
    // Calculate XOR distance between two node IDs
    fn calculate_xor_distance(&self, a: &NodeId, b: &NodeId) -> u32 {
        // Hash both node IDs for consistent distance
        let a_hash = quantum_resistant_hash(a.as_bytes());
        let b_hash = quantum_resistant_hash(b.as_bytes());
        
        // Use first 4 bytes as u32 distance (can be extended for more precision)
        let mut distance = 0u32;
        for i in 0..4.min(a_hash.len()).min(b_hash.len()) {
            let xor = a_hash[i] ^ b_hash[i];
            distance |= (xor as u32) << (i * 8);
        }
        
        distance
    }
    
    // Cleanup old and unreliable nodes
    pub fn cleanup_nodes(&self) -> usize {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        
        // Only clean up once per interval
        if last_cleanup.elapsed() < Self::CLEANUP_INTERVAL {
            return 0;
        }
        
        *last_cleanup = Instant::now();
        
        let mut to_remove = Vec::new();
        
        // Find nodes to remove
        {
            let nodes = self.nodes.read().unwrap();
            
            for (id, node) in nodes.iter() {
                // Remove nodes not seen in a long time
                if node.last_seen.elapsed() > Self::NODE_TIMEOUT {
                    to_remove.push(id.clone());
                    continue;
                }
                
                // Remove nodes with very low reputation and more failures than successes
                if node.reputation < 0.1 && node.failed_connections > node.successful_connections {
                    to_remove.push(id.clone());
                    continue;
                }
            }
        }
        
        // Remove nodes
        let removed_count = to_remove.len();
        
        if !to_remove.is_empty() {
            // Remove from nodes map
            {
                let mut nodes = self.nodes.write().unwrap();
                for id in &to_remove {
                    nodes.remove(id);
                }
            }
            
            // Remove from buckets
            {
                let mut buckets = self.buckets.write().unwrap();
                for id in &to_remove {
                    let bucket_idx = self.calculate_bucket_index(id);
                    if bucket_idx < buckets.len() {
                        buckets[bucket_idx].remove(id);
                    }
                }
            }
            
            info!("Cleaned up {} stale or unreliable nodes", removed_count);
        }
        
        removed_count
    }
    
    // Get all known nodes
    pub fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().unwrap();
        nodes.values()
            .map(|node| node.node_info.clone())
            .collect()
    }
    
    // Get node information by ID
    pub fn get_node(&self, node_id: &NodeId) -> Option<NodeInfo> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(node_id).map(|node| node.node_info.clone())
    }
    
    // Get node reputation
    pub fn get_node_reputation(&self, node_id: &NodeId) -> Option<f32> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(node_id).map(|node| node.reputation)
    }
    
    // Save node cache to disk
    pub fn save_node_cache(&self) -> Result<(), String> {
        if let Some(path) = &self.node_cache_file {
            let nodes = self.nodes.read().unwrap();
            
            // Only save nodes with good reputation
            let nodes_to_save: Vec<_> = nodes.values()
                .filter(|node| node.reputation > 0.3)
                .map(|node| (
                    node.node_info.clone(),
                    node.reputation,
                    node.successful_connections,
                    node.failed_connections,
                    node.verified
                ))
                .collect();
                
            // Serialize to file
            let file = std::fs::File::create(path)
                .map_err(|e| format!("Failed to create cache file: {}", e))?;
                
            bincode::serialize_into(file, &nodes_to_save)
                .map_err(|e| format!("Failed to serialize node cache: {}", e))?;
                
            info!("Saved {} nodes to cache {}", nodes_to_save.len(), path);
            Ok(())
        } else {
            Err("No cache file configured".to_string())
        }
    }
    
    // Load node cache from disk
    pub fn load_node_cache(&self) -> Result<usize, String> {
        if let Some(path) = &self.node_cache_file {
            // Check if file exists
            if !std::path::Path::new(path).exists() {
                return Ok(0);
            }
            
            // Open and deserialize file
            let file = std::fs::File::open(path)
                .map_err(|e| format!("Failed to open cache file: {}", e))?;
                
            let nodes_data: Vec<(NodeInfo, f32, u32, u32, bool)> = bincode::deserialize_from(file)
                .map_err(|e| format!("Failed to deserialize node cache: {}", e))?;
                
            // Add nodes to discovery
            let mut added = 0;
            for (node_info, reputation, success, failure, verified) in nodes_data {
                // Add node to discovery
                if self.add_node(node_info.clone(), verified) {
                    added += 1;
                    
                    // Update stats
                    let mut nodes = self.nodes.write().unwrap();
                    if let Some(node) = nodes.get_mut(&node_info.id) {
                        node.reputation = reputation;
                        node.successful_connections = success;
                        node.failed_connections = failure;
                    }
                }
            }
            
            info!("Loaded {} nodes from cache {}", added, path);
            Ok(added)
        } else {
            Err("No cache file configured".to_string())
        }
    }
    
    // Start active discovery process
    pub fn start_discovery(&self, network_manager: Arc<SecureNetworkManager>) -> Result<(), String> {
    if self.discovery_active.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return Err("Discovery already active".to_string());
    }
    
    let discovery = Arc::clone(&self.clone_into_arc());
    let network = network_manager;
    
    std::thread::spawn(move || {
            info!("Starting active discovery process");
            
            loop {
                // Check if discovery is still active
                if !discovery.discovery_active.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                
                // Get up to 3 random nodes to query
                let query_nodes = discovery.get_random_nodes(3);
                
                for node in query_nodes {
                    // Create discovery request message
                    let request = Message {
                        sender: network.as_ref().local_id().clone(),
                        message_type: MessageType::DiscoveryRequest,
                        payload: Vec::new(),
                    };
                    
                    // Send request
                    if let Err(e) = network.send_message(&node.id, request) {
                        debug!("Failed to send discovery request to {}: {}", node.id, e);
                        discovery.update_reputation(&node.id, false, None);
                    } else {
                        debug!("Sent discovery request to {}", node.id);
                    }
                }
                
                // Sleep between discovery rounds
                std::thread::sleep(Duration::from_secs(300)); // 5 minutes
                
                // Cleanup stale nodes
                discovery.cleanup_nodes();
                
                // Save node cache
                let _ = discovery.save_node_cache();
            }
            
            info!("Active discovery process stopped");
        });
        
        Ok(())
    }

    // Adicione um método para clonar para um Arc

fn clone_into_arc(&self) -> Arc<Self> {
    Arc::new(self.clone())
}
    
    // Stop active discovery
    pub fn stop_discovery(&self) {
        self.discovery_active.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    
    // Get random nodes for discovery
    fn get_random_nodes(&self, count: usize) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().unwrap();
        
        if nodes.is_empty() {
            return Vec::new();
        }
        
        let mut rng = rand::thread_rng();
        let mut result = Vec::with_capacity(count);
        
        // Get all node IDs as a vector
        let node_ids: Vec<_> = nodes.keys().collect();
        
        // Pick random nodes
        for _ in 0..count.min(nodes.len()) {
            let idx = rng.gen_range(0..node_ids.len());
            if let Some(node) = nodes.get(node_ids[idx]) {
                result.push(node.node_info.clone());
            }
        }
        
        result
    }
    
    // Process discovery response
    pub fn process_discovery_response(&self, from_node: &NodeId, nodes: Vec<NodeInfo>) -> usize {
        let mut added = 0;
        
        // Update reputation of responding node
        self.update_reputation(from_node, true, None);
        
        // Add received nodes
        for node in nodes {
            if self.add_node(node, false) {
                added += 1;
            }
        }
        
        added
    }
}