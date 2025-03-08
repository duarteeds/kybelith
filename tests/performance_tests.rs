use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use kybelith::p2p::MessageType;
use kybelith::p2p::network::SecureNetworkManager;
use kybelith::p2p::EnhancedP2PNetwork;
use kybelith::p2p::p2p_core::P2PConfig;
use rand::Rng;

// Estruturas para medição de performance
struct PerformanceMetrics {
    messages_sent: AtomicUsize,
    messages_received: AtomicUsize,
    bytes_sent: AtomicUsize,
    bytes_received: AtomicUsize,
    latencies_ms: Mutex<Vec<f64>>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            messages_sent: AtomicUsize::new(0),
            messages_received: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_received: AtomicUsize::new(0),
            latencies_ms: Mutex::new(Vec::new()),
        }
    }
    
    fn add_message_sent(&self, bytes: usize) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }
    
    fn add_message_received(&self, bytes: usize) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }
    
    fn add_latency(&self, latency_ms: f64) {
        let mut latencies = self.latencies_ms.lock().unwrap();
        latencies.push(latency_ms);
    }
    
    fn get_average_latency(&self) -> f64 {
        let latencies = self.latencies_ms.lock().unwrap();
        if latencies.is_empty() {
            return 0.0;
        }
        latencies.iter().sum::<f64>() / latencies.len() as f64
    }
    
    fn get_summary(&self) -> String {
        let avg_latency = self.get_average_latency();
        let msgs_sent = self.messages_sent.load(Ordering::Relaxed);
        let msgs_received = self.messages_received.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        
        format!(
            "Enviados: {} msgs ({} bytes), Recebidos: {} msgs ({} bytes), Latência média: {:.2}ms",
            msgs_sent, bytes_sent, msgs_received, bytes_received, avg_latency
        )
    }
}

// Teste de throughput com vários tamanhos de mensagens
#[test]
#[ignore] // Ignorar por padrão, execute com --ignored
fn test_message_throughput() {
    // Criar dois nós para teste
    let sender_config = P2PConfig {
        node_id: "throughput_sender".to_string(),
        listen_address: "127.0.0.1:7000".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 10,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let receiver_config = P2PConfig {
        node_id: "throughput_receiver".to_string(),
        listen_address: "127.0.0.1:7001".to_string(),
        seed_nodes: vec!["127.0.0.1:7000".to_string()],
        node_cache_path: None,
        max_connections: 10,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let sender = EnhancedP2PNetwork::new(sender_config).unwrap();
    let receiver = EnhancedP2PNetwork::new(receiver_config).unwrap();
    
    // Iniciar os nós
    sender.start().expect("Falha ao iniciar nó sender");
    receiver.start().expect("Falha ao iniciar nó receiver");
    
    // Aguardar conexão
    thread::sleep(Duration::from_secs(3));
    
    // Métricas de performance
    let metrics = Arc::new(PerformanceMetrics::new());
    
    // Testar diferentes tamanhos de mensagem
    let message_sizes = vec![100, 1000, 10000, 100000];
    let messages_per_size = 100;
    
    println!("Iniciando teste de throughput com {} mensagens por tamanho", messages_per_size);
    
    for &size in &message_sizes {
        println!("Testando mensagens de {} bytes", size);
        
        let start = Instant::now();
        let metrics_clone = Arc::clone(&metrics);
        
        // Enviar mensagens
        for _ in 0..messages_per_size {
            // Gerar payload aleatório do tamanho especificado
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill(&mut payload[..]);
            
            // Enviar mensagem
            let send_time = Instant::now();
            match sender.send_message(
                &"throughput_receiver".to_string(),
                MessageType::Heartbeat,
                payload.clone()
            ) {
                Ok(_) => {
                    metrics_clone.add_message_sent(size);
                    let elapsed = send_time.elapsed().as_secs_f64() * 1000.0; // ms
                    metrics_clone.add_latency(elapsed);
                },
                Err(e) => {
                    println!("Erro ao enviar mensagem: {}", e);
                }
            }
            
            // Pausa pequena para não sobrecarregar
            thread::sleep(Duration::from_millis(10));
        }
        
        let duration = start.elapsed();
        let throughput = (size * messages_per_size) as f64 / duration.as_secs_f64() / 1024.0; // KB/s
        
        println!(
            "Tamanho {} bytes: Enviadas {} mensagens em {:?} - Throughput: {:.2} KB/s",
            size,
            messages_per_size,
            duration,
            throughput
        );
    }
    
    // Aguardar processamento final
    thread::sleep(Duration::from_secs(2));
    
    println!("Métricas finais: {}", metrics.get_summary());
    
    // Limpar
    sender.stop().expect("Falha ao parar nó sender");
    receiver.stop().expect("Falha ao parar nó receiver");
}

// Teste de latência de rede
#[test]
#[ignore]
fn test_network_latency() {
    // Criar dois nós para teste
    let node1_config = P2PConfig {
        node_id: "latency_node1".to_string(),
        listen_address: "127.0.0.1:7100".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 10,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let node2_config = P2PConfig {
        node_id: "latency_node2".to_string(),
        listen_address: "127.0.0.1:7101".to_string(),
        seed_nodes: vec!["127.0.0.1:7100".to_string()],
        node_cache_path: None,
        max_connections: 10,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let node1 = EnhancedP2PNetwork::new(node1_config).unwrap();
    let node2 = EnhancedP2PNetwork::new(node2_config).unwrap();
    
    // Iniciar os nós
    node1.start().expect("Falha ao iniciar nó 1");
    node2.start().expect("Falha ao iniciar nó 2");
    
    // Aguardar conexão
    thread::sleep(Duration::from_secs(3));
    
    // Métricas de latência
    let latencies = Arc::new(Mutex::new(Vec::new()));
    
    // Enviar mensagens ping-pong
    let ping_count = 50;
    let payload = vec![1, 2, 3, 4]; // Pequeno payload
    
    println!("Enviando {} pings", ping_count);
    
    for i in 0..ping_count {
        let start = Instant::now();
        
        // Enviar ping
        match node1.send_message(
            &"latency_node2".to_string(),
            MessageType::Heartbeat,
            payload.clone()
        ) {
            Ok(_) => {},
            Err(e) => {
                println!("Erro ao enviar ping {}: {}", i, e);
                continue;
            }
        }
        
        // Aguardar pong (simulado com pausa)
        thread::sleep(Duration::from_millis(50));
        
        // Calcular RTT
        let rtt = start.elapsed().as_secs_f64() * 1000.0; // ms
        
        let mut latencies_guard = latencies.lock().unwrap();
        latencies_guard.push(rtt);
        
        // Pausa entre pings
        thread::sleep(Duration::from_millis(100));
    }
    
    // Calcular estatísticas
    let latencies_guard = latencies.lock().unwrap();
    
    if latencies_guard.is_empty() {
        println!("Nenhuma latência medida!");
    } else {
        let avg_latency: f64 = latencies_guard.iter().sum::<f64>() / latencies_guard.len() as f64;
        let max_latency = latencies_guard.iter().fold(0.0, |max, &val| max.max(val));
        let min_latency = latencies_guard.iter().fold(f64::MAX, |min, &val| min.min(val));
        
        println!(
            "Estatísticas de latência (ms) - Min: {:.2}, Média: {:.2}, Max: {:.2}",
            min_latency, avg_latency, max_latency
        );
    }
    
    // Limpar
    node1.stop().expect("Falha ao parar nó 1");
    node2.stop().expect("Falha ao parar nó 2");
}

// Teste de escalabilidade com muitos nós
#[test]
#[ignore]
fn test_scalability() {
    // Número de nós para testar
    let node_count = 20; // Ajuste conforme capacidade do sistema
    
    // Criar nós
    let mut nodes = Vec::with_capacity(node_count);
    
    println!("Criando {} nós para teste de escalabilidade", node_count);
    
    // Criar primeiro nó (seed)
    let seed_config = P2PConfig {
        node_id: "seed_node".to_string(),
        listen_address: "127.0.0.1:8000".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 100, // Alta para permitir muitas conexões
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let seed_node = EnhancedP2PNetwork::new(seed_config).unwrap();
    seed_node.start().expect("Falha ao iniciar seed node");
    nodes.push(seed_node);
    
    // Criar os outros nós conectando ao seed
    for i in 1..node_count {
        let config = P2PConfig {
            node_id: format!("scale_node_{}", i),
            listen_address: format!("127.0.0.1:{}", 8000 + i),
            seed_nodes: vec!["127.0.0.1:8000".to_string()],
            node_cache_path: None,
            max_connections: 20,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        match EnhancedP2PNetwork::new(config) {
            Ok(node) => {
                node.start().expect("Falha ao iniciar nó");
                nodes.push(node);
            },
            Err(e) => {
                println!("Erro ao criar nó {}: {}", i, e);
            }
        }
        
        // Breve pausa para não sobrecarregar durante inicialização
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("Todos os {} nós iniciados", nodes.len());
    
    // Aguardar tempo para formação da rede
    thread::sleep(Duration::from_secs(10));
    
    // Verificar número de conexões no seed node
    let connected = nodes[0].get_connected_nodes();
    println!("Seed node conectado a {} de {} nós", connected.len(), node_count - 1);
    
    // Testar broadcast a partir do seed
    let start = Instant::now();
    
    match nodes[0].broadcast_message(
        MessageType::Heartbeat,
        vec![1, 2, 3, 4]
    ) {
        Ok(count) => {
            println!("Broadcast enviado para {} nós", count);
        },
        Err(e) => {
            println!("Erro no broadcast: {}", e);
        }
    }
    
    // Aguardar propagação
    thread::sleep(Duration::from_secs(5));
    
    let duration = start.elapsed();
    println!("Propagação em rede de {} nós levou {:?}", nodes.len(), duration);
    
    // Limpar
    for node in &nodes {
        let _ = node.stop();
    }
}

// Teste de performance com criptografia pós-quântica
#[test]
#[ignore]
fn test_quantum_crypto_performance() {
    use kybelith::crypto::kyber::Kyber512;
    use kybelith::crypto::dilithium::Dilithium5;
    
    println!("Teste de performance da criptografia pós-quântica");
    
    // Criar instâncias das implementações criptográficas
    let kyber = Kyber512::new().unwrap();
    let dilithium = Dilithium5::new().unwrap();
    
    // 1. Teste de performance do Kyber (troca de chaves)
    println!("\n== Teste de performance Kyber (troca de chaves) ==");
    
    let iterations = 100;
    let start = Instant::now();
    
    for i in 0..iterations {
        // Gerar par de chaves
        let (pub_key, _priv_key) = kyber.keypair().unwrap();
        
        // Encapsular/decapsular
        let (_shared_secret, _ciphertext) = kyber.encapsulate(&pub_key).unwrap();
        
        if i % 10 == 0 {
            print!(".");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("\nKyber: {} operações em {:?} ({:.2} ops/s)", iterations, duration, ops_per_sec);
    
    // 2. Teste de performance do Dilithium (assinatura)
    println!("\n== Teste de performance Dilithium (assinatura) ==");
    
    // Usar menos iterações pois Dilithium é mais lento
    let iterations = 50;
    let start = Instant::now();
    
    // Gerar par de chaves uma vez
    let (pub_key, priv_key) = dilithium.keypair().unwrap();
    
    for i in 0..iterations {
        // Dados para assinar
        let data = format!("Test data for signing iteration {}", i).into_bytes();
        
        // Assinar
        let signature = dilithium.sign(&data, &priv_key).unwrap();
        
        // Verificar (parte mais intensiva)
        let result = dilithium.verify(&data, &signature, &pub_key).unwrap();
        assert!(result, "Falha na verificação de assinatura");
        
        if i % 5 == 0 {
            print!(".");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }
    
    let duration = start.elapsed();
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("\nDilithium: {} operações em {:?} ({:.2} ops/s)", iterations, duration, ops_per_sec);
}

// Teste de compressão de mensagens
#[test]
fn test_message_compression() {
    // Testar compressão com diferentes tipos de dados
    println!("Teste de performance da compressão de mensagens");
    
    // Tipos de dados para testar
    let test_cases = vec![
        ("Zeros", vec![0u8; 10000]), // Altamente compressível
        ("Random", rand::thread_rng().gen::<[u8; 10000]>().to_vec()), // Não compressível
        ("Repetitive", [1, 2, 3, 4, 5].repeat(2000)), // Moderadamente compressível
        ("JSON", r#"{"data": [{"id": 1, "name": "Test"}, {"id": 2, "name": "Test"}]}"#.repeat(100).into_bytes()), // Texto estruturado
    ];
    
    for (name, data) in test_cases {
        let original_size = data.len();
        
        // Medir tempo de compressão
        let start = Instant::now();
        let compressed = SecureNetworkManager::compress_message(&data).unwrap();
        let compression_time = start.elapsed();
        
        let compressed_size = compressed.len();
        let ratio = (compressed_size as f64 / original_size as f64) * 100.0;
        
        println!(
            "{}: Original {} bytes, Comprimido {} bytes ({:.2}%), Tempo: {:?}",
            name, original_size, compressed_size, ratio, compression_time
        );
        
        // Verificar se a compressão é reversível (para dados compressíveis)
        if compressed_size < original_size {
            let network = SecureNetworkManager::new(
                "127.0.0.1:0",
                "test_compression".to_string(),
                vec![0; 32],
            ).unwrap();
            
            let decompressed = network.decompress_message(&compressed, true).unwrap();
            assert_eq!(decompressed, data, "Falha na descompressão");
        }
    }
}

// Teste de performance sob carga crescente
#[test]
#[ignore]
fn test_increasing_load() {
    // Criar uma rede com alguns nós
    let node_count = 5;
    let mut nodes = Vec::with_capacity(node_count);
    
    println!("Criando {} nós para teste de carga", node_count);
    
    // Criar primeiro nó (seed)
    let seed_config = P2PConfig {
        node_id: "load_seed".to_string(),
        listen_address: "127.0.0.1:8100".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 50,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let seed_node = EnhancedP2PNetwork::new(seed_config).unwrap();
    seed_node.start().expect("Falha ao iniciar seed node");
    nodes.push(seed_node);
    
    // Criar os outros nós
    for i in 1..node_count {
        let config = P2PConfig {
            node_id: format!("load_node_{}", i),
            listen_address: format!("127.0.0.1:{}", 8100 + i),
            seed_nodes: vec!["127.0.0.1:8100".to_string()],
            node_cache_path: None,
            max_connections: 20,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        let node = EnhancedP2PNetwork::new(config).unwrap();
        node.start().expect("Falha ao iniciar nó");
        nodes.push(node);
        
        thread::sleep(Duration::from_millis(100));
    }
    
    // Aguardar conexões
    thread::sleep(Duration::from_secs(3));
    
    // Testar com carga crescente
    let msg_sizes = vec![100, 1000, 5000, 10000, 50000];
    let send_intervals_ms = vec![500, 200, 100, 50, 20];
    
    for (size_idx, &msg_size) in msg_sizes.iter().enumerate() {
        if size_idx >= send_intervals_ms.len() {
            break;
        }
        
        let interval_ms = send_intervals_ms[size_idx];
        println!(
            "Testando com mensagens de {} bytes, intervalo {}ms", 
            msg_size, interval_ms
        );
        
        // Enviar mensagens por 5 segundos
        let end_time = Instant::now() + Duration::from_secs(5);
        let mut sent_count = 0;
        
        while Instant::now() < end_time {
            // Escolher um nó aleatório para enviar
            let sender_idx = rand::thread_rng().gen_range(0..nodes.len());
            
            // Dados aleatórios
            let data = vec![0u8; msg_size];
            
            // Enviar para todos os outros nós
            for i in 0..nodes.len() {
                if i == sender_idx {
                    continue;
                }
                
                match nodes[sender_idx].send_message(
                    &nodes[i].local_id.clone(),
                    MessageType::Heartbeat,
                    data.clone()
                ) {
                    Ok(_) => sent_count += 1,
                    Err(e) => {
                        println!("Erro ao enviar: {}", e);
                    }
                }
            }
            
            // Aguardar intervalo
            thread::sleep(Duration::from_millis(interval_ms));
        }
        
        println!("Enviadas {} mensagens de {} bytes em 5 segundos", sent_count, msg_size);
        
        // Pausa entre testes
        thread::sleep(Duration::from_secs(2));
    }
    
    // Limpar
    for node in &nodes {
        let _ = node.stop();
    }
}

// Teste de uso de memória sob carga
#[test]
#[ignore]
fn test_memory_usage() {
    // Este teste exige instrumentação externa para monitorar memória
    println!("Teste de uso de memória - execute com ferramentas como valgrind/heaptrack");
    
    // Criar um nó
    let config = P2PConfig {
        node_id: "memory_test_node".to_string(),
        listen_address: "127.0.0.1:8200".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 50,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let network = EnhancedP2PNetwork::new(config).unwrap();
    network.start().expect("Falha ao iniciar nó");
    
    // Adicionar muitas mensagens à rede
    let iterations = 10000;
    let message_size = 10000; // 10KB
    
    println!("Gerando {} mensagens de {}KB", iterations, message_size / 1024);
    
    for i in 0..iterations {
        let data = vec![i as u8 % 255; message_size];
        
        // Broadcast (não irá realmente enviar por falta de peers)
        let _ = network.broadcast_message(
            MessageType::Heartbeat,
            data
        );
        
        if i % 1000 == 0 {
            print!(".");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }
    
    println!("\nTodas as mensagens enfileiradas, aguardando processamento...");
    thread::sleep(Duration::from_secs(10));
    
    // Ciclo de GC manual
    println!("Tentando liberar memória...");
    network.stop().expect("Falha ao parar nó");
    
    // Aguardar finalização
    thread::sleep(Duration::from_secs(5));
    println!("Teste concluído - verificar métricas de memória externamente");
}

// Teste de estabilidade em execução longa
#[test]
#[ignore]
fn test_long_running_stability() {
    // Este teste deve rodar por um longo período
    // Talvez seja melhor executá-lo manualmente ou como parte de CI especial
    
    println!("Iniciando teste de estabilidade de longo prazo");
    println!("Este teste irá executar por 30 minutos");
    
    // Criar alguns nós
    let mut nodes = Vec::new();
    
    // Criar nó central
    let seed_config = P2PConfig {
        node_id: "stability_seed".to_string(),
        listen_address: "127.0.0.1:8300".to_string(),
        seed_nodes: vec![],
        node_cache_path: None,
        max_connections: 50,
        enable_bridges: false,
        trusted_peers: vec![],
    };
    
    let seed_node = EnhancedP2PNetwork::new(seed_config).unwrap();
    seed_node.start().expect("Falha ao iniciar seed node");
    nodes.push(seed_node);
    
    // Criar alguns nós adicionais
    for i in 1..5 {
        let config = P2PConfig {
            node_id: format!("stability_node_{}", i),
            listen_address: format!("127.0.0.1:{}", 8300 + i),
            seed_nodes: vec!["127.0.0.1:8300".to_string()],
            node_cache_path: None,
            max_connections: 20,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        let node = EnhancedP2PNetwork::new(config).unwrap();
        node.start().expect("Falha ao iniciar nó");
        nodes.push(node);
        
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("Rede inicializada com {} nós", nodes.len());
    
    // Hora de início
    let start_time = Instant::now();
    let test_duration = Duration::from_secs(30 * 60); // 30 minutos
    
    // Contadores
    let message_counter = Arc::new(AtomicUsize::new(0));
    let error_counter = Arc::new(AtomicUsize::new(0));
    
    // Thread para monitorar
    let message_counter_clone = Arc::clone(&message_counter);
    let error_counter_clone = Arc::clone(&error_counter);
    
    let monitor_thread = thread::spawn(move || {
        let start = Instant::now();
        
        while start.elapsed() < test_duration {
            let msgs = message_counter_clone.load(Ordering::Relaxed);
            let errs = error_counter_clone.load(Ordering::Relaxed);
            
            println!(
                "[{}s] Status: {} mensagens enviadas, {} erros", 
                start.elapsed().as_secs(),
                msgs,
                errs
            );
            
            thread::sleep(Duration::from_secs(60)); // Log a cada minuto
        }
    });
    
    // Loop principal - enviar mensagens periodicamente
    let mut rng = rand::thread_rng();
    
    while start_time.elapsed() < test_duration {
        // Selecionar nó aleatório como remetente
        let sender_idx = rng.gen_range(0..nodes.len());
        
        // Selecionar nó aleatório como destinatário
        let mut receiver_idx = rng.gen_range(0..nodes.len());
        while receiver_idx == sender_idx {
            receiver_idx = rng.gen_range(0..nodes.len());
        }
        
        // Criar mensagem de tamanho aleatório
        let size = rng.gen_range(100..10000);
        let data = vec![0u8; size];
        
        // Enviar mensagem
        match nodes[sender_idx].send_message(
            &nodes[receiver_idx].local_id.clone(),
            MessageType::Heartbeat,
            data
        ) {
            Ok(_) => {
                message_counter.fetch_add(1, Ordering::Relaxed);
            },
            Err(_) => {
                error_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Pausa aleatória entre envios
        let sleep_ms = rng.gen_range(100..1000);
        thread::sleep(Duration::from_millis(sleep_ms));
    }
    
    // Aguardar thread de monitoramento
    let _ = monitor_thread.join();
    
    // Resultados finais
    let msgs = message_counter.load(Ordering::Relaxed);
    let errs = error_counter.load(Ordering::Relaxed);
    
    println!(
        "Teste de estabilidade concluído após {:?}",
        start_time.elapsed()
    );
    println!(
        "Total: {} mensagens enviadas, {} erros ({:.2}% taxa de erro)",
        msgs,
        errs,
        (errs as f64 / msgs as f64) * 100.0
    );
    
    // Limpar
    for node in &nodes {
        let _ = node.stop();
    }
}