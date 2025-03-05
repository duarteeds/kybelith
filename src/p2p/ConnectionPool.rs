use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::net::TcpStream;
use std::io::{Read, Write, Result as IoResult};
use crate::p2p::types::{NodeId, NodeInfo};
use log::{info, error};
use chacha20poly1305::ChaCha20Poly1305;

pub struct Connection {
    stream: TcpStream,
    node_info: NodeInfo,
    cipher: ChaCha20Poly1305,
    last_activity: std::time::Instant,
}

#[derive(Debug, Clone)]
pub struct NetworkHealthReport {
    pub timestamp: u64,
    pub total_connections: usize,
    pub total_messages: u64,
    pub total_bytes: u64,
    pub avg_connection_age: u64, // 
    pub suspicious_nodes_count: usize,
}

impl Connection {
    pub fn new(stream: TcpStream, node_info: NodeInfo, cipher: ChaCha20Poly1305) -> Self {
        Self {
            stream,
            node_info,
            cipher,
            last_activity: std::time::Instant::now(),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> IoResult<()> {
        self.stream.write_all(data)?;
        self.stream.flush()?;
        self.last_activity = std::time::Instant::now();
        Ok(())
    }

    pub fn receive(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let bytes_read = self.stream.read(buffer)?;
        if bytes_read > 0 {
            self.last_activity = std::time::Instant::now();
        }
        Ok(bytes_read)
    }

    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    pub fn get_node_info(&self) -> &NodeInfo {
        &self.node_info
    }

    pub fn get_cipher(&self) -> &ChaCha20Poly1305 {
        &self.cipher
    }
}

pub struct ConnectionPool {
    connections: Arc<RwLock<HashMap<NodeId, Arc<Mutex<Connection>>>>>,
    idle_timeout: std::time::Duration,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout: std::time::Duration::from_secs(600), // 10 minutos por padrão
        }
    }

    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout: std::time::Duration::from_secs(timeout_secs),
        }
    }

    pub fn add_connection(&self, node_id: NodeId, stream: TcpStream, 
                          node_info: NodeInfo, cipher: ChaCha20Poly1305) {
        let connection = Connection::new(stream, node_info, cipher);
        let mut connections = self.connections.write().unwrap();
        connections.insert(node_id.clone(), Arc::new(Mutex::new(connection)));
        info!("Added connection to node: {}", node_id);
    }

    pub fn check_connection_health(&self, node_id: &NodeId) -> bool {
        if let Some(conn) = self.get_connection(node_id) {
            let conn_guard = match conn.lock() {
                Ok(guard) => guard,
                Err(_) => return false, // Poisoned mutex indicates dead connection
            };
            
            // Check if connection is alive by attempting a lightweight ping
            let mut ping_buffer = [0; 1];
            match conn_guard.stream.peek(&mut ping_buffer) {
                Ok(_) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn remove_connection(&self, node_id: &NodeId) -> bool {
        let mut connections = self.connections.write().unwrap();
        let removed = connections.remove(node_id).is_some();
        if removed {
            info!("Removed connection to node: {}", node_id);
        }
        removed
    }

    pub fn get_connection(&self, node_id: &NodeId) -> Option<Arc<Mutex<Connection>>> {
        let connections = self.connections.read().unwrap();
        connections.get(node_id).cloned()
    }

    pub fn get_connection_duration(&self, node_id: &NodeId) -> Option<Duration> {
    let metrics_read = match self.metrics.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de leitura para métricas: {}", e);
            return None;
        }
    };
    
    metrics_read.get(node_id).map(|metrics| {
        metrics.first_connected.elapsed()
    })
}

// Método para detectar conexões anômalas
pub fn detect_anomalous_connections(&self) -> Vec<(NodeId, String)> {
    let metrics_read = match self.metrics.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de leitura para métricas: {}", e);
            return Vec::new();
        }
    };
    
    let nodes_read = match self.nodes.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("Falha ao adquirir lock de leitura para nós: {}", e);
            return Vec::new();
        }
    };
    
    let mut suspicious = Vec::new();
    
    for (node_id, metrics) in metrics_read.iter() {
        // Conexão muito recente com alto volume de tráfego = suspeita
        if metrics.first_connected.elapsed() < Duration::from_secs(60) && 
           metrics.bytes_sent + metrics.bytes_received > 1_000_000 {
            suspicious.push((node_id.clone(), "Alto volume de tráfego em conexão nova".to_string()));
        }
        
        // Taxa muito alta de mensagens enviadas/recebidas
        if metrics.messages_received > 0 {
            let messages_per_second = metrics.messages_received as f64 / 
                                      metrics.first_connected.elapsed().as_secs_f64();
            
            if messages_per_second > 100.0 { // Mais de 100 mensagens por segundo
                suspicious.push((node_id.clone(), 
                    format!("Taxa de mensagens suspeita: {:.2} msg/s", messages_per_second)));
            }
        }
        
        // Muitas falhas de comunicação
        if metrics.failures > 5 {
            suspicious.push((node_id.clone(), 
                format!("Alto número de falhas de comunicação: {}", metrics.failures)));
        }
        
        // Verificar se o endereço IP está em uma lista de bloqueio
        if let Some((info, _)) = nodes_read.get(node_id) {
            let ip = info.address.ip().to_string();
            if self.is_ip_blocked(&ip) {
                suspicious.push((node_id.clone(), 
                    format!("IP na lista de bloqueio: {}", ip)));
            }
        }
    }
    
    suspicious
}

// Método auxiliar para verificar IP bloqueado (exemplo simplificado)
fn is_ip_blocked(&self, ip: &str) -> bool {
    // Lista de IPs suspeitos (em uma implementação real, isso viria de um banco de dados
    // ou de uma API externa de reputação de IPs)
    let blocked_ips = ["1.2.3.4", "5.6.7.8"];
    blocked_ips.contains(&ip)
}


pub fn generate_network_health_report(&self) -> NetworkHealthReport {
    let metrics_read = self.metrics.read().unwrap();
    let nodes_read = self.nodes.read().unwrap();
    
    let total_connections = nodes_read.len();
    let total_messages = metrics_read.values()
        .map(|m| m.messages_sent + m.messages_received)
        .sum::<u64>();
    
    let total_bytes = metrics_read.values()
        .map(|m| m.bytes_sent + m.bytes_received)
        .sum::<u64>();
    
    let avg_connection_age = if !metrics_read.is_empty() {
        metrics_read.values()
            .map(|m| m.first_connected.elapsed().as_secs())
            .sum::<u64>() / metrics_read.len() as u64
    } else {
        0
    };
    
    let suspicious_nodes = self.detect_anomalous_connections();
    
    NetworkHealthReport {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        total_connections,
        total_messages,
        total_bytes,
        avg_connection_age,
        suspicious_nodes_count: suspicious_nodes.len(),
    }
}

    pub fn send_to(&self, node_id: &NodeId, data: &[u8]) -> IoResult<()> {
        if let Some(conn) = self.get_connection(node_id) {
            let mut conn = conn.lock().unwrap();
            conn.send(data)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No connection to node {}", node_id)
            ))
        }
    }

    pub fn get_all_connections(&self) -> Vec<(NodeId, Arc<Mutex<Connection>>)> {
        let connections = self.connections.read().unwrap();
        connections.iter()
            .map(|(id, conn)| (id.clone(), conn.clone()))
            .collect()
    }

    pub fn cleanup_idle_connections(&self) -> usize {
        let mut to_remove = Vec::new();
        
        // First phase: identify connections to remove (read lock)
        {
            let connections = match self.connections.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire read lock for connections: {}", e);
                    return 0;
                }
            };
            
            for (node_id, conn) in connections.iter() {
                // Avoid blocking on potentially deadlocked connections
                let conn_guard = match conn.try_lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        // Connection mutex is locked or poisoned - mark for removal
                        to_remove.push(node_id.clone());
                        continue;
                    }
                };
                
                if conn_guard.is_idle(self.idle_timeout) {
                    to_remove.push(node_id.clone());
                }
            }
        }
        
        // Second phase: remove identified connections (write lock)
        let mut removed = 0;
        {
            let mut connections = match self.connections.write() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire write lock for connections: {}", e);
                    return 0;
                }
            };
            
            for node_id in &to_remove {
                if connections.remove(node_id).is_some() {
                    info!("Removed idle connection to node: {}", node_id);
                    removed += 1;
                }
            }
        }
        
        removed
    }

    pub fn health_check_all(&self) -> (usize, usize) {
        let mut checked = 0;
        let mut recovered = 0;
        let connections = match self.connections.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire read lock for health check: {}", e);
                return (0, 0);
            }
        };
        
        for (node_id, conn) in connections.iter() {
            checked += 1;
            
            // Skip if connection is clearly healthy
            let conn_guard = match conn.try_lock() {
                Ok(guard) => guard,
                Err(_) => continue, // Skip locked connections
            };
            
            // Check last activity
            if conn_guard.last_activity.elapsed() > Duration::from_secs(30) {
                // Send heartbeat packet to verify connection
                let heartbeat = [0; 1]; // Minimal heartbeat packet
                if conn_guard.send(&heartbeat).is_ok() {
                    recovered += 1;
                }
            }
        }
        
        (checked, recovered)
    }

    pub fn start_cleanup_task(pool: Arc<ConnectionPool>, initial_interval_secs: u64) {
        std::thread::spawn(move || {
            let mut interval = std::time::Duration::from_secs(initial_interval_secs);
            let min_interval = std::time::Duration::from_secs(10);
            let max_interval = std::time::Duration::from_secs(300);
            
            loop {
                std::thread::sleep(interval);
                
                // Perform cleanup and health check
                let removed = pool.cleanup_idle_connections();
                let (checked, recovered) = pool.health_check_all();
                
                // Adaptive interval based on connection health
                if removed > 0 || recovered > 0 {
                    // More activity - check more frequently
                    interval = std::cmp::max(interval / 2, min_interval);
                    info!("Connection activity detected: removed={}, recovered={}. Increasing check frequency.", 
                          removed, recovered);
                } else if checked > 0 {
                    // No issues - check less frequently
                    interval = std::cmp::min(interval * 5 / 4, max_interval);
                }
                
                info!("Connection health: checked={}, healthy={}, removed={}", 
                      checked, checked - removed, removed);
            }
        });
    }
}