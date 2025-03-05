use std::net::TcpStream;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use log::{info, error, warn};
use serde::{Serialize, Deserialize};
use rand::{Rng, RngCore};
use chacha20poly1305::{ChaCha20Poly1305, AeadCore, KeyInit, aead::Aead};
use crate::p2p::network::SecureNetworkManager;
use sha3::Digest;
use crate::crypto::kyber::Kyber512;
use crate::crypto::dilithium::Dilithium5;
use crate::p2p::types::NodeId;
use std::sync::atomic::{AtomicBool, Ordering};


/// Enum para representar os protocolos de blockchain suportados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainProtocol {
    Kybelith,
    Bitcoin,
    Ethereum,
    Polkadot,
    Cosmos,
    // Adicione mais protocolos conforme necessário
}

/// Informações sobre uma blockchain externa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalChainInfo {
    /// Nome identificador da blockchain
    pub name: String,
    /// Protocolo utilizado pela blockchain
    pub protocol: BlockchainProtocol,
    /// Endereço de conexão com a blockchain
    pub connection_address: String,
    /// Versão do protocolo
    pub protocol_version: String,
    /// Tipo de consenso
    pub consensus_type: String,
    /// Timestamp da última sincronização
    pub last_sync: u64,
    /// Status da conexão
    pub connection_status: ConnectionStatus,
}

/// Status da conexão com uma blockchain externa
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
}

/// Mensagem para comunicação entre blockchains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMessage {
    /// ID da mensagem
    pub message_id: String,
    /// Blockchain de origem
    pub source_chain: String,
    /// Blockchain de destino
    pub target_chain: String,
    /// Tipo de mensagem
    pub message_type: CrossChainMessageType,
    /// Dados da mensagem
    pub payload: Vec<u8>,
    /// Assinatura da mensagem
    pub signature: Vec<u8>,
    /// Timestamp da mensagem
    pub timestamp: u64,
}

/// Tipos de mensagens entre blockchains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossChainMessageType {
    /// Solicitação de transferência de ativos
    AssetTransfer,
    /// Execução de contrato entre blockchains
    ContractExecution,
    /// Verificação de prova
    ProofVerification,
    /// Atualização de estado
    StateUpdate,
    /// Sincronização de cabeçalho
    HeaderSync,
    /// Mensagem personalizada
    Custom(String),
}

/// Gerencia as pontes entre diferentes blockchains
pub struct BridgeManager {
    /// Mapa de bridges indexado pelo nome da blockchain externa
    bridges: HashMap<String, Arc<Bridge>>,
    /// Cipher para criptografia local
    local_cipher: ChaCha20Poly1305,
    /// ID local
    local_id: NodeId,
    /// Kyber para encriptação pós-quântica
    kyber: Kyber512,
    /// Dilithium para assinaturas pós-quânticas
    dilithium: Dilithium5,
    /// Callback para processar mensagens recebidas
    message_callback: Arc<Mutex<Option<Box<dyn Fn(CrossChainMessage) -> Result<(), String> + Send + Sync>>>>,
    signing_keys: Mutex<(Vec<u8>, Vec<u8>)>, //
    private_key: Mutex<Option<Vec<u8>>>, // 
}

impl BridgeManager {
    /// Maximum message size to prevent DoS attacks
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    /// Cria um novo gerenciador de bridges
    pub fn new(local_id: NodeId) -> Result<Self, Box<dyn std::error::Error>> {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let local_cipher = ChaCha20Poly1305::new(&key_bytes.into());
    
    let kyber = Kyber512::new()?;
    let dilithium = Dilithium5::new()?;
    
    let (public_key_vec, private_key_vec) = dilithium.keypair()?;
    
    Ok(Self { 
        bridges: HashMap::new(),
        local_cipher,
        local_id,
        kyber,
        dilithium,
        message_callback: Arc::new(Mutex::new(None)),
        signing_keys: Mutex::new((public_key_vec, private_key_vec)),
        private_key: Mutex::new(None),
    })
}

    pub fn integrate_with_network(&mut self, network: Arc<Mutex<SecureNetworkManager>>) -> Result<(), String> {
        let network_clone: Arc<Mutex<SecureNetworkManager>> = Arc::clone(&network);
        self.set_message_handler(move |msg| {
            let network = network_clone.lock().unwrap();
            network.propagate_cross_chain_message(msg.clone())?;
            Ok(())
        });
        Ok(())
    }
       
    /// Adiciona uma bridge para uma blockchain externa
    pub fn add_bridge(&mut self, chain_info: ExternalChainInfo) -> Result<(), String> {
        if self.bridges.contains_key(&chain_info.name) {
            return Err(format!("Bridge para '{}' já existe", chain_info.name));
        }
        
        let bridge = Bridge::new(
            chain_info,
            self.local_id.clone(),
            self.kyber.clone(),
            self.dilithium.clone(),
        )?;
        
        self.bridges.insert(bridge.get_chain_info().name.clone(), Arc::new(bridge));
        Ok(())
    }

    /// Remove uma bridge
    pub fn remove_bridge(&mut self, chain_name: &str) -> Result<(), String> {
        if !self.bridges.contains_key(chain_name) {
            return Err(format!("Bridge para '{}' não encontrada", chain_name));
        }
        
        // Desconectar antes de remover
        if let Some(bridge) = self.bridges.get(chain_name) {
            bridge.disconnect()?;
        }
        
        self.bridges.remove(chain_name);
        Ok(())
    }

    /// Conecta a todas as bridges configuradas
    pub fn connect_all(&self) -> Vec<Result<(), String>> {
        let mut results = Vec::new();
        
        for (chain_name, bridge) in &self.bridges {
            match bridge.connect() {
                Ok(_) => {
                    info!("Conectado à blockchain externa '{}'", chain_name);
                    results.push(Ok(()));
                }
                Err(e) => {
                    error!("Falha ao conectar à blockchain '{}': {}", chain_name, e);
                    results.push(Err(e));
                }
            }
        }
        
        results
    }

    /// Retorna o nome da cadeia primária
    pub fn get_chain_name(&self) -> String {
        "primary-chain".to_string()
    }

    /// Conecta a uma ponte específica com tratamento de erros
    pub fn connect(&self) -> Result<(), String> {
        let results = self.connect_all();
        
        // Verifica se houve algum erro nas conexões
        for result in &results {
            if let Err(err) = result {
                return Err(format!("Connection error: {}", err));
            }
        }
        
        // Se todas as conexões foram bem-sucedidas
        if !results.is_empty() {
            Ok(())
        } else {
            Err("No bridges to connect".to_string())
        }
    }

    /// Tenta reconectar com backoff exponencial
   pub fn reconnect_with_backoff(&self, max_attempts: u32) -> Result<(), String> {
    let mut attempt = 0;
    let mut backoff_ms = 100; // Inicial: 100ms
    
    while attempt < max_attempts {
        info!("Reconnection attempt {} for {}", attempt + 1, self.get_chain_name());
        
        match self.connect() {
            Ok(_) => return Ok(()),
            Err(e) => {
                error!("Reconnection failed: {}", e);
                attempt += 1;
                
                // Backoff exponencial com jitter
                let jitter = rand::thread_rng().gen_range(0..100);
                let sleep_time = backoff_ms + jitter;
                
                thread::sleep(Duration::from_millis(sleep_time));
                
                // Aumentar backoff para a próxima tentativa (máximo 30s)
                backoff_ms = std::cmp::min(backoff_ms * 2, 30000);
            }
        }
    }
    
    Err(format!("Failed to reconnect after {} attempts", max_attempts))
}


    /// Envia uma mensagem para uma blockchain específica
    pub fn send_message(&self, message: CrossChainMessage) -> Result<(), String> {
        // Verificar se conectado à cadeia de destino
        if let Some(bridge) = self.bridges.get(&message.target_chain) {
            // Assinar a mensagem usando nossas chaves Dilithium
            let message_with_signature = self.sign_message(message)?;
            
            // Criptografar a mensagem com a cifra local antes de enviar
            let encrypted_message = self.encrypt_message(&message_with_signature)?;
            
            // Enviar através da bridge
            bridge.send_message(encrypted_message)
        } else {
            Err(format!("Bridge para '{}' não encontrada", message.target_chain))
        }
    }

    fn sign_message(&self, mut message: CrossChainMessage) -> Result<CrossChainMessage, String> {
        // Serializar a mensagem sem a assinatura para assinar
        let mut message_copy = message.clone();
        message_copy.signature = Vec::new(); // Limpar assinatura existente
        
        let message_bytes = bincode::serialize(&message_copy)
            .map_err(|e| format!("Falha ao serializar mensagem para assinatura: {}", e))?;
        
        // Assinar usando Dilithium com nossa chave privada
        let (_, private_key) = *self.signing_keys.lock().unwrap();
        
        let signature = self.dilithium.sign(&message_bytes, private_key)
            .map_err(|e| format!("Falha ao assinar mensagem: {}", e))?;
        
        // Adicionar assinatura à mensagem
        message.signature = signature.to_vec();
        
        Ok(message)
    }

    fn encrypt_message(&self, message: &CrossChainMessage) -> Result<CrossChainMessage, String> {
        // Serializar a mensagem completa com assinatura
        let message_bytes = bincode::serialize(message)
            .map_err(|e| format!("Falha ao serializar mensagem para cifragem: {}", e))?;
        
        // Gerar nonce aleatório
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        
        // Criptografar a mensagem
        let ciphertext = self.local_cipher.encrypt(&nonce, message_bytes.as_slice())
            .map_err(|e| format!("Falha ao cifrar mensagem: {}", e))?;
        
        // Criar mensagem criptografada
        let encrypted_message = CrossChainMessage {
            message_id: format!("enc_{}", message.message_id),
            source_chain: message.source_chain.clone(),
            target_chain: message.target_chain.clone(),
            message_type: message.message_type.clone(),
            payload: ciphertext,      // Payload contém a mensagem criptografada
            signature: nonce.to_vec(), // Armazenar nonce na assinatura (temporário)
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        Ok(encrypted_message)
    }

    pub fn verify_message(&self, message: &CrossChainMessage) -> Result<bool, String> {
        // Obter a chave pública da blockchain de origem
        let source_public_key = self.get_chain_public_key(&message.source_chain)?;
        
        // Criar cópia da mensagem sem assinatura
        let mut message_copy = message.clone();
        let signature = message_copy.signature.clone();
        message_copy.signature = Vec::new();
        
        // Serializar mensagem para verificação
        let message_bytes = bincode::serialize(&message_copy)
            .map_err(|e| format!("Falha ao serializar mensagem para verificação: {}", e))?;
        
        // Verificar assinatura
        self.dilithium.verify(&message_bytes, &signature, &source_public_key)
            .map_err(|e| format!("Falha ao verificar assinatura: {}", e))
    }

    // Método auxiliar para obter chave pública de uma blockchain
    fn get_chain_public_key(&self, chain_name: &str) -> Result<Vec<u8>, String> {
        // Em uma implementação real, buscar de um armazenamento seguro
        // Aqui, apenas simulamos diferentes chaves para diferentes cadeias
        
        match chain_name {
            "Ethereum" => Ok(vec![1u8; 32]),
            "Polkadot" => Ok(vec![2u8; 32]),
            "Cosmos" => Ok(vec![3u8; 32]),
            "Bitcoin" => Ok(vec![4u8; 32]),
            "Kybelith" => {
                // Usar nossa própria chave pública
                Ok(self.signing_keys.lock().unwrap().0.clone())
            },
            _ => Err(format!("Chave pública não disponível para blockchain '{}'", chain_name)),
        }
    }

    // Método para inicializar rotação de chaves periódica
    pub fn start_key_rotation_scheduler(&self, interval_mins: u64) -> Result<(), String> {
        let chain_name = self.get_chain_name();
    let interval = interval_mins;

std::thread::spawn(move || {
    loop {
                
                std::thread::sleep(Duration::from_secs(interval * 60));
            info!("Scheduled key rotation for {}", chain_name);
    
            }
        });
        
        Ok(())
    }

    fn rotate_keys(&self) -> Result<(), String> {
    let (new_public_key, new_private_key) = self.dilithium.keypair()
        .map_err(|e| format!("Falha ao gerar novo par de chaves: {}", e.into()))?;

    let mut keys = self.signing_keys.lock()
        .map_err(|e| format!("Falha ao obter lock das chaves: {}", e))?;
    keys.0 = new_public_key;
    keys.1 = new_private_key;

    let mut priv_key = self.private_key.lock()
        .map_err(|e| format!("Falha ao obter lock da chave privada: {}", e))?;
    *priv_key = Some(new_private_key);

    for (chain_name, bridge) in &self.bridges {
        let key_update_message = CrossChainMessage {
            message_id: format!("key_rotation_{}", uuid::Uuid::new_v4()),
            source_chain: "Kybelith".to_string(),
            target_chain: chain_name.clone(),
            message_type: CrossChainMessageType::Custom("key_rotation".to_string()),
            payload: keys.0.clone(),
            signature: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        bridge.send_message(self.sign_message(key_update_message)?)
            .map_err(|e| format!("Falha ao enviar atualização para {}: {}", chain_name, e))?;
    }

    info!("Rotação de chaves concluída com nova chave privada");
    Ok(())
}

    /// Processa uma mensagem recebida da blockchain externa
    pub fn process_received_message(&self, chain_name: &str, message: CrossChainMessage) -> Result<(), String> {
        // Primeiro, processa a mensagem na bridge específica
        if let Some(bridge) = self.bridges.get(chain_name) {
            bridge.process_received_message(message.clone())?;
        } else {
            return Err(format!("Bridge para '{}' não encontrada", chain_name));
        }
        
        // Depois, chama o callback global se estiver configurado
        let callback = self.message_callback.lock().unwrap();
        match &*callback {
            Some(handler) => handler(message),
            None => {
                warn!("Nenhum handler configurado para mensagens entre blockchains");
                Ok(())
            }
        }
    }

    /// Define o callback para processar mensagens recebidas
    pub fn set_message_handler<F>(&mut self, handler: F)
    where
        F: Fn(CrossChainMessage) -> Result<(), String> + Send + Sync + 'static,
    {
        let mut callback = self.message_callback.lock().unwrap();
        *callback = Some(Box::new(handler));
    }

    /// Obtém informações sobre todas as bridges
    pub fn get_bridges_info(&self) -> Vec<ExternalChainInfo> {
        self.bridges.values()
            .map(|bridge| bridge.get_chain_info())
            .collect()
    }

    /// Verifica o status de uma bridge específica
    pub fn check_bridge_status(&self, chain_name: &str) -> Result<ConnectionStatus, String> {
        if let Some(bridge) = self.bridges.get(chain_name) {
            Ok(bridge.get_status())
        } else {
            Err(format!("Bridge para '{}' não encontrada", chain_name))
        }
    }
}

/// Dados para o handshake inicial
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeData {
    /// Versão do protocolo
    protocol_version: String,
    /// ID do nó
    node_id: String,
    /// Chave pública para troca de chaves
    public_key: Vec<u8>,
    /// Timestamp da mensagem
    timestamp: u64,
    /// Nome da blockchain
    chain_name: String,
}

/// Mensagem completa de handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeMessage {
    /// Dados do handshake
    data: HandshakeData,
    /// Assinatura dos dados
    signature: Vec<u8>,
}

/// Representa uma ponte para comunicação com uma blockchain externa
pub struct Bridge {
    /// Informações sobre a blockchain externa
    chain_info: RwLock<ExternalChainInfo>,
    /// Conexão TCP com a blockchain externa
    connection: Mutex<Option<TcpStream>>,
    /// ID do nó local
    local_id: NodeId,
    /// Kyber para encriptação
    kyber: Kyber512,
    /// Dilithium para assinaturas
    dilithium: Dilithium5,
    /// Chave compartilhada com a blockchain externa
    shared_key: RwLock<Option<Vec<u8>>>,
    /// Par de chaves para assinatura
    signing_keys: (Vec<u8>, Vec<u8>), // (public_key, private_key)
}

impl Clone for Bridge {
    fn clone(&self) -> Self {
        // Criar nova instância com mesmos parâmetros
        // Nota: Isso não clona a conexão TCP, apenas as informações
        let chain_info = self.chain_info.read().unwrap().clone();
        
        Self {
            chain_info: RwLock::new(chain_info),
            connection: Mutex::new(None),
            local_id: self.local_id.clone(),
            kyber: self.kyber.clone(),
            dilithium: self.dilithium.clone(),
            shared_key: RwLock::new(None),
            signing_keys: self.signing_keys.clone(),
        }
    }
}

impl Bridge {
    // Constantes
    const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB

    
    /// Cria uma nova bridge
    pub fn new(
        chain_info: ExternalChainInfo,
        local_id: NodeId,
        kyber: Kyber512,
        dilithium: Dilithium5,
    ) -> Result<Self, String> {
        // Gerar par de chaves para assinatura
        let (public_key, private_key) = kyber.keypair()
            .map_err(|e| format!("Falha ao gerar par de chaves Kyber: {}", e))?;

        Ok(Self {
            chain_info: RwLock::new(chain_info),
            connection: Mutex::new(None),
            local_id,
            kyber,
            dilithium,
            shared_key: RwLock::new(None),
            signing_keys: (public_key.into_vec(), private_key.into_vec()),
        })
    }

    /// Retorna informações sobre a blockchain conectada
    pub fn get_chain_info(&self) -> ExternalChainInfo {
        self.chain_info.read().unwrap().clone()
    }

    /// Retorna o nome da blockchain
    pub fn get_chain_name(&self) -> String {
        self.chain_info.read().unwrap().name.clone()
    }

    /// Retorna o status da conexão
    pub fn get_status(&self) -> ConnectionStatus {
        self.chain_info.read().unwrap().connection_status.clone()
    }

    /// Tenta reconectar com backoff exponencial
    pub fn reconnect_with_backoff(&self, max_attempts: u32) -> Result<(), String> {
        let mut attempt = 0;
        let mut backoff_ms = 100; // Tempo inicial de backoff: 100ms
        
        while attempt < max_attempts {
            info!("Tentativa de reconexão {} para {}", attempt + 1, self.get_chain_name());
            
            // Tenta estabelecer uma conexão TCP com timeout
            let stream_result = TcpStream::connect_timeout(
                &self.get_chain_info().connection_address.parse()
                    .map_err(|e| format!("Endereço inválido: {}", e))?,
                Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS)
            );
            
            match stream_result {
                Ok(mut stream) => {
                    // Configura timeouts no socket
                    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS))) {
                        error!("Falha ao definir timeout de leitura: {}", e);
                        attempt += 1;
                        thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = std::cmp::min(backoff_ms * 2, 30000); // Máximo de 30s
                        continue;
                    }
                    
                    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS))) {
                        error!("Falha ao definir timeout de escrita: {}", e);
                        attempt += 1;
                        thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = std::cmp::min(backoff_ms * 2, 30000);
                        continue;
                    }
                    
                    // Usa o stream para enviar uma mensagem inicial (exemplo de uso da variável)
                    if let Err(e) = stream.write_all(b"INIT") {
                        error!("Falha ao enviar mensagem inicial: {}", e);
                        attempt += 1;
                        thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = std::cmp::min(backoff_ms * 2, 30000);
                        continue;
                    }
                    stream.flush().map_err(|e| format!("Falha ao flush stream: {}", e))?;
                    info!("Mensagem inicial enviada para {}", self.get_chain_name());
                    
                    // Realiza o handshake
                    match self.perform_handshake(&stream) {
                        Ok((shared_key, _cipher)) => {
                            // Configura a conexão bem-sucedida
                            {
                                let mut shared = self.shared_key.write().unwrap();
                                *shared = Some(shared_key);
                            }
                            {
                                let mut conn = self.connection.lock().unwrap();
                                *conn = Some(stream); // Armazena o stream para uso futuro
                            }
                            {
                                let mut info = self.chain_info.write().unwrap();
                                info.connection_status = ConnectionStatus::Connected;
                                info.last_sync = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                            }
                            
                            info!("Reconexão bem-sucedida na tentativa {}", attempt + 1);
                            self.start_listener(); // Inicia o listener
                            return Ok(());
                        },
                        Err(e) => {
                            warn!("Handshake falhou na tentativa {}: {}", attempt + 1, e);
                            attempt += 1;
                        }
                    }
                },
                Err(e) => {
                    warn!("Falha na conexão na tentativa {}: {}", attempt + 1, e);
                    attempt += 1;
                }
            }
            
            // Aplica backoff com jitter se a tentativa falhar
            let jitter = rand::thread_rng().gen_range(0..100);
            let sleep_time = backoff_ms + jitter;
            info!("Aguardando {}ms antes da próxima tentativa", sleep_time);
            thread::sleep(Duration::from_millis(sleep_time));
            
            // Aumenta o backoff para a próxima tentativa, com limite de 30 segundos
            backoff_ms = std::cmp::min(backoff_ms * 2, 30000);
        }
        
        Err(format!("Falha ao reconectar após {} tentativas", max_attempts))
    }

    /// Conecta à blockchain externa
    pub fn connect(&self) -> Result<(), String> {
        let mut info = self.chain_info.write().unwrap();
        
        // Early return if already connected
        if info.connection_status == ConnectionStatus::Connected {
            return Ok(());
        }

        // Atualizar status para "conectando"
        info.connection_status = ConnectionStatus::Connecting;
        drop(info); // Libera o lock antes de prosseguir

        // Tenta conectar via TCP
        let stream = match TcpStream::connect_timeout(
            &self.get_chain_info().connection_address.parse()
                .map_err(|e| format!("Invalid address: {}", e))?,
            Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS)
        ) {
            Ok(s) => s,
            Err(e) => {
                // Se a conexão falhar, tentar com backoff e jitter
                match self.reconnect_with_backoff(3) { // Tenta reconectar até 3 vezes
                    Ok(()) => {
                        // Se reconectou com sucesso, retorne Ok
                        return Ok(());
                    }
                    Err(_) => {
                        // Se ainda falhar, atualizar o status e retornar o erro original
                        let mut info = self.chain_info.write().unwrap();
                        info.connection_status = ConnectionStatus::Error(e.to_string());
                        return Err(format!("Connection failed: {}", e));
                    }
                }
            }
        };

        // Configurar socket
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS))) {
            let mut info = self.chain_info.write().unwrap();
            info.connection_status = ConnectionStatus::Error(e.to_string());
            return Err(format!("Failed to set read timeout: {}", e));
        }
        
        if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(Self::HANDSHAKE_TIMEOUT_SECS))) {
            let mut info = self.chain_info.write().unwrap();
            info.connection_status = ConnectionStatus::Error(e.to_string());
            return Err(format!("Failed to set write timeout: {}", e));
        }
        
        // Realizar handshake seguro com a blockchain externa
        match self.perform_handshake(&stream) {
            Ok((shared_key, _cipher)) => {
                // Configura a conexão bem-sucedida
                {
                    let mut shared = self.shared_key.write().unwrap();
                    *shared = Some(shared_key);
                }
                
                let mut conn = self.connection.lock().unwrap();
                *conn = Some(stream);
                
                let mut info = self.chain_info.write().unwrap();
                info.connection_status = ConnectionStatus::Connected;
                info.last_sync = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                // Iniciar thread para escutar mensagens
                self.start_listener();
                
                Ok(())
            },
            Err(e) => {
                let mut info = self.chain_info.write().unwrap();
                info.connection_status = ConnectionStatus::Error(e.clone());
                Err(e)
            }
        }
    }

    /// Desconecta da blockchain externa
    pub fn disconnect(&self) -> Result<(), String> {
        let mut conn = self.connection.lock().unwrap();
        if conn.is_none() {
            return Ok(());
        }

        // Fechar conexão
        *conn = None;
        
        // Limpar chave compartilhada
        let mut shared = self.shared_key.write().unwrap();
        *shared = None;
        
        // Atualizar status
        let mut info = self.chain_info.write().unwrap();
        info.connection_status = ConnectionStatus::Disconnected;
        
        Ok(())
    }
    
    /// Realiza o handshake com a blockchain externa usando criptografia pós-quântica
    fn perform_handshake(&self, stream: &TcpStream) -> Result<(Vec<u8>, ChaCha20Poly1305), String> {
    // Gerar par de chaves Kyber para troca de chaves
    let (ephemeral_pk, ephemeral_sk) = self.kyber.keypair()
        .map_err(|e| format!("Falha ao gerar par de chaves: {}", e))?;
    
    // Criar mensagem de handshake
    let nonce: [u8; 32] = rand::random();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    // Converter ephemeral_pk para bytes uma única vez (PublicKey usa into_vec)
    let ephemeral_pk_bytes = ephemeral_pk.into_vec();
    
    // Criar mensagem para sign (node_id + ephemeral_pk + nonce + timestamp)
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(self.local_id.as_bytes());
    auth_data.extend_from_slice(&ephemeral_pk_bytes);
    auth_data.extend_from_slice(&nonce);
    auth_data.extend_from_slice(&timestamp.to_be_bytes());
    
    // Sign with Dilithium for quantum security
    let signature = self.dilithium.sign(&auth_data, &self.signing_keys.1)
        .map_err(|e| format!("Falha ao assinar handshake: {}", e))?;
    
    // Create handshake message
    let handshake_data = HandshakeData {
        protocol_version: "2.0.0".to_string(), // Upgraded protocol version
        node_id: self.local_id.clone(),
        public_key: ephemeral_pk_bytes.clone(), // Usar clone aqui pois estamos reutilizando
        timestamp,
        chain_name: self.get_chain_name().to_string(),
    };
    
    let handshake_message = HandshakeMessage {
        data: handshake_data,
        signature,
    };
    
    // Serialize message
    let message_bytes = bincode::serialize(&handshake_message)
        .map_err(|e| format!("Falha ao serializar handshake: {}", e))?;
    
    // Send message length followed by message
    let length = message_bytes.len() as u32;
    let mut stream_clone = stream.try_clone()
        .map_err(|e| format!("Falha ao clonar stream: {}", e))?;
        
    stream_clone.write_all(&length.to_be_bytes())
        .map_err(|e| format!("Falha ao enviar length: {}", e))?;
        
    stream_clone.write_all(&message_bytes)
        .map_err(|e| format!("Falha ao enviar handshake: {}", e))?;
        
    stream_clone.flush()
        .map_err(|e| format!("Falha ao flush stream: {}", e))?;
    
    // Read response length
    let mut length_bytes = [0u8; 4];
    stream_clone.read_exact(&mut length_bytes)
        .map_err(|e| format!("Falha ao ler response length: {}", e))?;
        
    let length = u32::from_be_bytes(length_bytes) as usize;
    
    // Validate response size
    if length > 10 * 1024 * 1024 { // 10MB max
        return Err("Response too large".to_string());
    }
    
    // Read response
    let mut response_bytes = vec![0u8; length];
    stream_clone.read_exact(&mut response_bytes)
        .map_err(|e| format!("Falha ao ler response: {}", e))?;
        
    // Deserialize response
    let response: HandshakeMessage = bincode::deserialize(&response_bytes)
        .map_err(|e| format!("Falha ao deserializar response: {}", e))?;
    
    // Verify response timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    if response.data.timestamp > now + 10 {
        return Err("Response timestamp is in the future".to_string());
    }
    
    if now - response.data.timestamp > 30 {
        return Err("Response timestamp is too old".to_string());
    }
    
    // Convert remote public key for encapsulation
    let _remote_pk = self.kyber.public_key_from_bytes(&response.data.public_key)
        .map_err(|e| format!("Failed to convert remote public key: {}", e))?;
    
    // Encapsulate shared secret - converta PublicKey para bytes ou use método apropriado
    let remote_pk_bytes = &response.data.public_key; // Usamos os bytes originais
    
    let encapsulation_result = self.kyber.encapsulate(remote_pk_bytes)
        .map_err(|e| format!("Failed to encapsulate key: {}", e))?;
        
    let (shared_secret, _ciphertext) = encapsulation_result;
    
    // Create a combined secret using static and ephemeral keys
    // Use SHA3-256 for quantum resistance
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&shared_secret);
    
    // Clone secretKey antes de consumir com into_vec
    let ephemeral_sk_bytes = ephemeral_sk.clone().into_vec();
    hasher.update(&ephemeral_sk_bytes);
    hasher.update(&nonce);
    
    let final_secret = hasher.finalize().to_vec();
    
    // Criar o cipher com a chave compartilhada
    let cipher = ChaCha20Poly1305::new_from_slice(&final_secret[..32])
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    
    // Retornar a tupla contendo o segredo final e o cipher
    Ok((final_secret, cipher))
}

    /// Inicia uma thread para escutar mensagens da blockchain externa
   fn start_listener(&self) {
    let chain_name = self.get_chain_name();
    let bridge_arc = Arc::new(self.clone());
    
    std::thread::spawn(move || {
        info!("Iniciando listener para blockchain '{}'", chain_name);
        
        // Flag para controlar o loop (necessária para substituir self.running)
        let running = Arc::new(AtomicBool::new(true));
        
        while running.load(Ordering::SeqCst) {
            // Verificar se a conexão está ativa
            {
                let conn = bridge_arc.connection.lock().unwrap();
                if conn.is_none() {
                    info!("Conexão não está ativa, encerrando listener para '{}'", chain_name);
                    break;
                }
            }
            
            // Tentar receber uma mensagem
            match bridge_arc.receive_message() {
                Ok(message) => {
                    info!("Mensagem recebida de '{}': {:?}", chain_name, message.message_type);
                    
                    // Verificar tamanho máximo da mensagem
                    if message.payload.len() > Self::MAX_MESSAGE_SIZE {
                        error!(
                            "Mensagem de '{}' excede o tamanho máximo permitido ({} bytes): {} bytes",
                            chain_name, Self::MAX_MESSAGE_SIZE, message.payload.len()
                        );
                        continue;
                    }
                    
                    // Processar a mensagem recebida
                    if let Err(e) = bridge_arc.process_received_message(message) {
                        error!("Erro ao processar mensagem de '{}': {}", chain_name, e);
                    }
                }
                Err(e) => {
                    // Lidar com diferentes tipos de erros
                    if e.contains("timeout") || e.contains("would block") {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        continue;
                    }
                    
                    error!("Erro ao receber mensagem de '{}': {}", chain_name, e);
                    
                    // Tentar reconectar se a conexão foi perdida
                    if e.contains("connection reset") || e.contains("broken pipe") {
                        error!("Conexão perdida com '{}', tentando reconectar...", chain_name);
                        
                        // Atualizar status da conexão
                        {
                            let mut info = bridge_arc.chain_info.write().unwrap();
                            info.connection_status = ConnectionStatus::Disconnected;
                        }
                        
                        // Tentar reconectar
                        match bridge_arc.reconnect_with_backoff(3) {
                            Ok(()) => {
                                info!("Reconexão bem-sucedida com '{}'", chain_name);
                                continue;
                            }
                            Err(reconnect_err) => {
                                error!("Falha ao reconectar com '{}': {}", chain_name, reconnect_err);
                                break;
                            }
                        }
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        continue;
                    }
                }
            }
        }
        
        info!("Listener para '{}' finalizado", chain_name);
    });
}
   
    /// Envia uma mensagem para a blockchain externa
    pub fn send_message(&self, message: CrossChainMessage) -> Result<(), String> {
        // Verificar se estamos conectados
        let conn = self.connection.lock().unwrap();
        let stream = match &*conn {
            Some(s) => s,
            None => return Err("Não conectado à blockchain externa".to_string()),
        };
        
        // Verificar se temos uma chave compartilhada
        let shared_key = {
            let key = self.shared_key.read().unwrap();
            match &*key {
                Some(k) => k.clone(),
                None => return Err("Chave compartilhada não disponível".to_string()),
            }
        };
        
        // Serializar a mensagem
        let message_bytes = bincode::serialize(&message)
            .map_err(|e| format!("Falha ao serializar mensagem: {}", e))?;
        
        // Criar nonce para criptografia
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        
        // Criar cifrador com a chave compartilhada
        let key_bytes = &shared_key[..32]; // Primeiros 32 bytes
        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes)
            .map_err(|e| format!("Falha ao criar cifrador: {}", e))?;
        
        // Cifrar a mensagem
        let encrypted_data = cipher.encrypt(&nonce, message_bytes.as_slice())
            .map_err(|e| format!("Falha ao cifrar mensagem: {}", e))?;
        
        // Prefixar o nonce aos dados criptografados para decriptação
        let mut data_to_send = nonce.to_vec();
        data_to_send.extend_from_slice(&encrypted_data);
        
        // Enviar a mensagem
        let mut stream_clone = stream.try_clone()
            .map_err(|e| format!("Falha ao clonar stream: {}", e))?;
        
        stream_clone.write_all(&data_to_send)
            .map_err(|e| format!("Falha ao enviar mensagem: {}", e))?;
        stream_clone.flush()
            .map_err(|e| format!("Falha ao flush stream: {}", e))?;
        
        info!("Mensagem cifrada enviada para '{}'", self.get_chain_name());
        Ok(())
    }

    /// Processa uma mensagem recebida da blockchain externa
    pub fn process_received_message(&self, message: CrossChainMessage) -> Result<(), String> {
        if message.target_chain != "Kybelith" {
            warn!("Mensagem recebida não é destinada a esta blockchain: {:?}", message);
            return Ok(());
        }
        
        match message.message_type {
            CrossChainMessageType::AssetTransfer => {
                info!("Processando transferência de ativos da blockchain '{}'", message.source_chain);
            }
            CrossChainMessageType::ContractExecution => {
                info!("Processando execução de contrato da blockchain '{}'", message.source_chain);
            }
            // Outros casos...
            _ => {
                info!("Processando mensagem do tipo {:?} da blockchain '{}'", 
                      message.message_type, message.source_chain);
            }
        }
        Ok(())
    }

    /// Recebe uma mensagem da blockchain externa
    fn receive_message(&self) -> Result<CrossChainMessage, String> {
    // Verificar se estamos conectados
    let conn = self.connection.lock().unwrap();
    let stream = match &*conn {
        Some(s) => s,
        None => return Err("Não conectado à blockchain externa".to_string()),
    };
    
    // Verificar se temos uma chave compartilhada
    let shared_key = {
        let key = self.shared_key.read().unwrap();
        match &*key {
            Some(k) => k.clone(),
            None => return Err("Chave compartilhada não disponível".to_string()),
        }
    };
    
    // Ler dados do stream
    let mut stream_clone = stream.try_clone()
        .map_err(|e| format!("Falha ao clonar stream: {}", e))?;
    
    // Primeiro ler o nonce
    let mut nonce = [0u8; 12]; // Tamanho do nonce para ChaCha20Poly1305
    if let Err(e) = stream_clone.read_exact(&mut nonce) {
        return Err(format!("Falha ao ler nonce: {}", e));
    }
    
    // Ler o resto dos dados cifrados
    let mut buffer = [0u8; 8192];
    let bytes_read = stream_clone.read(&mut buffer)
        .map_err(|e| format!("Falha ao ler do stream: {}", e))?;
    
    if bytes_read == 0 {
        return Err("Conexão fechada pelo peer".to_string());
    }
    
    // Criar cifrador com a chave compartilhada
    let key_bytes = &shared_key[..32];
    let cipher = ChaCha20Poly1305::new_from_slice(key_bytes)
        .map_err(|e| format!("Falha ao criar cifrador: {}", e))?;
    
    // Decifrar a mensagem
    let decrypted_data = cipher.decrypt(&nonce.into(), &buffer[..bytes_read])
        .map_err(|e| format!("Falha ao decifrar mensagem: {}", e))?;
    
    // Desserializar a mensagem
    let message: CrossChainMessage = bincode::deserialize(&decrypted_data)
        .map_err(|e| format!("Falha ao desserializar mensagem: {}", e))?;
    
    // Verificar tamanho máximo da mensagem
    if message.payload.len() > Self::MAX_MESSAGE_SIZE {
        return Err(format!("Mensagem excede o tamanho máximo permitido: {} bytes (máximo: {} bytes)",
            message.payload.len(), Self::MAX_MESSAGE_SIZE));
    }
    
    // Verificar e processar a mensagem
    self.verify_and_process_message(message.clone())?;
    
    Ok(message)
}

    // Implementação do process_message para realmente processar a mensagem
    fn verify_and_process_message(&self, message: CrossChainMessage) -> Result<(), String> {
        let source_chain_info = {
            // lógica real para buscar a chave pública da blockchain de origem
            let public_key: Vec<u8> = vec![]; // Placeholder
            public_key
        };
        
        if message.target_chain != "Kybelith" {
            warn!("Mensagem recebida não é destinada a esta blockchain: {:?}", message);
            return Ok(());
        }
        
        let serialized = bincode::serialize(&message.payload).unwrap();
        self.dilithium.verify(&serialized, &message.signature, &source_chain_info)
            .map_err(|e| format!("Falha na verificação da assinatura: {}", e))?;
        
        self.process_received_message(message)
    }
}