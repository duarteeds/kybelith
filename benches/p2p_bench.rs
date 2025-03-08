use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use kybelith::p2p::message::Message;
use kybelith::p2p::MessageType;
use kybelith::p2p::network::SecureNetworkManager;
use kybelith::p2p::discovery::EnhancedNodeDiscovery;
use kybelith::p2p::EnhancedP2PNetwork;
use kybelith::p2p::p2p_core::P2PConfig;
use kybelith::crypto::kyber::Kyber512;
use kybelith::crypto::dilithium::Dilithium5;

// Estrutura para armazenar resultados de benchmark
struct BenchmarkResults {
    name: String,
    timestamp: u64,
    metrics: HashMap<String, f64>,
    details: String,
}

impl BenchmarkResults {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metrics: HashMap::new(),
            details: String::new(),
        }
    }
    
    fn add_metric(&mut self, name: &str, value: f64) {
        self.metrics.insert(name.to_string(), value);
    }
    
    fn add_detail(&mut self, detail: &str) {
        self.details.push_str(detail);
        self.details.push('\n');
    }
    
    fn to_json(&self) -> String {
        let mut json = format!(
            r#"{{"name":"{}", "timestamp":{}, "metrics":{{"#,
            self.name, self.timestamp
        );
        
        let mut first = true;
        for (k, v) in &self.metrics {
            if !first {
                json.push_str(", ");
            }
            first = false;
            json.push_str(&format!(r#""{}": {}"#, k, v));
        }
        
        json.push_str("}, \"details\": \"");
        
        // Escapar aspas
        let escaped_details = self.details.replace('\"', "\\\"").replace('\n', "\\n");
        json.push_str(&escaped_details);
        
        json.push_str("\"}}");
        json
    }
    
    fn to_csv_row(&self) -> String {
        let mut row = format!("{},{}", self.name, self.timestamp);
        
        // Certifique-se de manter a ordem das colunas
        for (k, v) in &self.metrics {
            row.push_str(&format!(",{}", v));
        }
        
        row
    }
    
    fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let json = self.to_json();
        let filename = format!(
            "{}/benchmark_{}_{}.json",
            path, 
            self.name,
            self.timestamp
        );
        
        let mut file = File::create(filename)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

// Trait para definir um benchmark
trait P2PBenchmark {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self) -> BenchmarkResults;
}

// Benchmark para troca de mensagens
struct MessageThroughputBenchmark {
    message_sizes: Vec<usize>,
    iterations: usize,
}

impl MessageThroughputBenchmark {
    fn new() -> Self {
        Self {
            message_sizes: vec![100, 1000, 10000, 100000],
            iterations: 100,
        }
    }
}

impl P2PBenchmark for MessageThroughputBenchmark {
    fn name(&self) -> &str {
        "message_throughput"
    }
    
    fn description(&self) -> &str {
        "Mede a capacidade de processamento de mensagens em diferentes tamanhos"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        results.add_detail(&format!("Execu��o: {} itera��es por tamanho", self.iterations));
        
        // Configurar n�s
        let node1_config = P2PConfig {
            node_id: "bench_node1".to_string(),
            listen_address: "127.0.0.1:7500".to_string(),
            seed_nodes: vec![],
            node_cache_path: None,
            max_connections: 10,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        let node2_config = P2PConfig {
            node_id: "bench_node2".to_string(),
            listen_address: "127.0.0.1:7501".to_string(),
            seed_nodes: vec!["127.0.0.1:7500".to_string()],
            node_cache_path: None,
            max_connections: 10,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        let node1 = match EnhancedP2PNetwork::new(node1_config) {
            Ok(n) => n,
            Err(e) => {
                results.add_detail(&format!("Erro ao criar n� 1: {}", e));
                return results;
            }
        };
        
        let node2 = match EnhancedP2PNetwork::new(node2_config) {
            Ok(n) => n,
            Err(e) => {
                results.add_detail(&format!("Erro ao criar n� 2: {}", e));
                return results;
            }
        };
        
        // Iniciar n�s
        if let Err(e) = node1.start() {
            results.add_detail(&format!("Erro ao iniciar n� 1: {}", e));
            return results;
        }
        
        if let Err(e) = node2.start() {
            results.add_detail(&format!("Erro ao iniciar n� 2: {}", e));
            node1.stop().unwrap();
            return results;
        }
        
        // Aguardar conex�o
        thread::sleep(Duration::from_secs(3));
        results.add_detail("N�s iniciados e conectados");
        
        // Testar cada tamanho de mensagem
        for &size in &self.message_sizes {
            results.add_detail(&format!("\nTestando mensagens de {} bytes", size));
            
            let data = vec![0u8; size];
            let start = Instant::now();
            let mut success_count = 0;
            
            // Enviar mensagens
            for i in 0..self.iterations {
                match node1.send_message(
                    &"bench_node2".to_string(),
                    MessageType::Heartbeat,
                    data.clone()
                ) {
                    Ok(_) => {
                        success_count += 1;
                    },
                    Err(e) => {
                        results.add_detail(&format!("Erro na itera��o {}: {}", i, e));
                    }
                }
                
                // Pequena pausa
                thread::sleep(Duration::from_millis(10));
            }
            
            let duration = start.elapsed();
            let throughput_bytes_per_sec = (size * success_count) as f64 / duration.as_secs_f64();
            let throughput_kb_per_sec = throughput_bytes_per_sec / 1024.0;
            let throughput_msgs_per_sec = success_count as f64 / duration.as_secs_f64();
            
            // Adicionar m�tricas
            results.add_metric(
                &format!("throughput_kb_per_sec_{}", size),
                throughput_kb_per_sec
            );
            
            results.add_metric(
                &format!("msgs_per_sec_{}", size),
                throughput_msgs_per_sec
            );
            
            results.add_detail(&format!(
                "Tamanho {}: {} msgs em {:?} - {:.2} KB/s ({:.2} msgs/s)",
                size,
                success_count,
                duration,
                throughput_kb_per_sec,
                throughput_msgs_per_sec
            ));
        }
        
        // Calcular m�dia geral
        let mut total_kb_per_sec = 0.0;
        let mut count = 0;
        
        for size in &self.message_sizes {
            let key = format!("throughput_kb_per_sec_{}", size);
            if let Some(&value) = results.metrics.get(&key) {
                total_kb_per_sec += value;
                count += 1;
            }
        }
        
        if count > 0 {
            results.add_metric(
                "avg_throughput_kb_per_sec", 
                total_kb_per_sec / count as f64
            );
        }
        
        // Limpar
        let _ = node1.stop();
        let _ = node2.stop();
        
        results
    }
}

// Benchmark para criptografia p�s-qu�ntica
struct QuantumCryptoBenchmark {
    kyber_iterations: usize,
    dilithium_iterations: usize,
}

impl QuantumCryptoBenchmark {
    fn new() -> Self {
        Self {
            kyber_iterations: 100,
            dilithium_iterations: 50,
        }
    }
}

impl P2PBenchmark for QuantumCryptoBenchmark {
    fn name(&self) -> &str {
        "quantum_crypto"
    }
    
    fn description(&self) -> &str {
        "Mede a performance da criptografia p�s-qu�ntica (Kyber e Dilithium)"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        // Inicializar os algoritmos criptogr�ficos
        let kyber = match Kyber512::new() {
            Ok(k) => k,
            Err(e) => {
                results.add_detail(&format!("Erro ao inicializar Kyber: {}", e));
                return results;
            }
        };
        
        let dilithium = match Dilithium5::new() {
            Ok(d) => d,
            Err(e) => {
                results.add_detail(&format!("Erro ao inicializar Dilithium: {}", e));
                return results;
            }
        };
        
        // 1. Benchmark Kyber (troca de chaves)
        results.add_detail(&format!("Executando benchmark Kyber com {} itera��es", self.kyber_iterations));
        
        let start = Instant::now();
        
        for i in 0..self.kyber_iterations {
            // Gerar par de chaves
            let keypair_result = kyber.keypair();
            if let Err(e) = keypair_result {
                results.add_detail(&format!("Erro na gera��o de chaves Kyber (itera��o {}): {}", i, e));
                continue;
            }
            
            let (pub_key, _priv_key) = keypair_result.unwrap();
            
            // Encapsular segredo compartilhado
            let encap_result = kyber.encapsulate(&pub_key);
            if let Err(e) = encap_result {
                results.add_detail(&format!("Erro na encapsula��o Kyber (itera��o {}): {}", i, e));
                continue;
            }
        }
        
        let kyber_duration = start.elapsed();
        let kyber_ops_per_sec = self.kyber_iterations as f64 / kyber_duration.as_secs_f64();
        
        results.add_metric("kyber_ops_per_sec", kyber_ops_per_sec);
        results.add_detail(&format!(
            "Kyber: {} opera��es em {:?} ({:.2} ops/s)",
            self.kyber_iterations, kyber_duration, kyber_ops_per_sec
        ));
        
        // 2. Benchmark Dilithium (assinaturas)
        results.add_detail(&format!("Executando benchmark Dilithium com {} itera��es", self.dilithium_iterations));
        
        // Gerar par de chaves uma vez (parte mais lenta)
        let keypair_result = dilithium.keypair();
        if let Err(e) = keypair_result {
            results.add_detail(&format!("Erro na gera��o de chaves Dilithium: {}", e));
            return results;
        }
        
        let (pub_key, priv_key) = keypair_result.unwrap();
        
        // Medir separadamente assinatura e verifica��o
        let start_sign = Instant::now();
        let mut signatures = Vec::with_capacity(self.dilithium_iterations);
        let test_data = b"Test data for signature benchmarking";
        
        for i in 0..self.dilithium_iterations {
            let sign_result = dilithium.sign(test_data, &priv_key);
            
            if let Err(e) = sign_result {
                results.add_detail(&format!("Erro na assinatura Dilithium (itera��o {}): {}", i, e));
                continue;
            }
            
            signatures.push(sign_result.unwrap());
        }
        
        let sign_duration = start_sign.elapsed();
        let sign_ops_per_sec = self.dilithium_iterations as f64 / sign_duration.as_secs_f64();
        
        results.add_metric("dilithium_sign_ops_per_sec", sign_ops_per_sec);
        results.add_detail(&format!(
            "Dilithium (assinatura): {} opera��es em {:?} ({:.2} ops/s)",
            self.dilithium_iterations, sign_duration, sign_ops_per_sec
        ));
        
        // Medir verifica��o
        let start_verify = Instant::now();
        let mut verify_success = 0;
        
        for (i, signature) in signatures.iter().enumerate() {
            let verify_result = dilithium.verify(test_data, signature, &pub_key);
            
            match verify_result {
                Ok(true) => verify_success += 1,
                Ok(false) => results.add_detail(&format!("Verifica��o falhou (itera��o {})", i)),
                Err(e) => results.add_detail(&format!("Erro na verifica��o (itera��o {}): {}", i, e)),
            }
        }
        
        let verify_duration = start_verify.elapsed();
        let verify_ops_per_sec = signatures.len() as f64 / verify_duration.as_secs_f64();
        
        results.add_metric("dilithium_verify_ops_per_sec", verify_ops_per_sec);
        results.add_detail(&format!(
            "Dilithium (verifica��o): {} opera��es em {:?} ({:.2} ops/s)",
            signatures.len(), verify_duration, verify_ops_per_sec
        ));
        
        results
    }
}

// Benchmark de escalabilidade da rede P2P
struct NetworkScalabilityBenchmark {
    node_counts: Vec<usize>,
    message_count: usize,
}

impl NetworkScalabilityBenchmark {
    fn new() -> Self {
        Self {
            node_counts: vec![3, 5, 10],  // Tamanhos de rede para testar
            message_count: 50,            // Mensagens a enviar por teste
        }
    }
}

impl P2PBenchmark for NetworkScalabilityBenchmark {
    fn name(&self) -> &str {
        "network_scalability"
    }
    
    fn description(&self) -> &str {
        "Mede a escalabilidade da rede P2P com diferentes n�meros de n�s"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        for &node_count in &self.node_counts {
            results.add_detail(&format!("\nTestando rede com {} n�s", node_count));
            
            // Criar n�s
            let mut nodes = Vec::with_capacity(node_count);
            let seed_port = 7700;
            
            // Criar primeiro n� (seed)
            let seed_config = P2PConfig {
                node_id: "scale_seed".to_string(),
                listen_address: format!("127.0.0.1:{}", seed_port),
                seed_nodes: vec![],
                node_cache_path: None,
                max_connections: 50,
                enable_bridges: false,
                trusted_peers: vec![],
            };
            
            match EnhancedP2PNetwork::new(seed_config) {
                Ok(node) => {
                    if let Err(e) = node.start() {
                        results.add_detail(&format!("Erro ao iniciar n� seed: {}", e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar n� seed: {}", e));
                    continue;
                }
            }
            
            // Criar os outros n�s
            for i in 1..node_count {
                let config = P2PConfig {
                    node_id: format!("scale_node_{}", i),
                    listen_address: format!("127.0.0.1:{}", seed_port + i),
                    seed_nodes: vec![format!("127.0.0.1:{}", seed_port)],
                    node_cache_path: None,
                    max_connections: 20,
                    enable_bridges: false,
                    trusted_peers: vec![],
                };
                
                match EnhancedP2PNetwork::new(config) {
                    Ok(node) => {
                        if let Err(e) = node.start() {
                            results.add_detail(&format!("Erro ao iniciar n� {}: {}", i, e));
                            continue;
                        }
                        nodes.push(node);
                    },
                    Err(e) => {
                        results.add_detail(&format!("Erro ao criar n� {}: {}", i, e));
                        continue;
                    }
                }
                
                // Pequena pausa para n�o sobrecarregar
                thread::sleep(Duration::from_millis(100));
            }
            
            results.add_detail(&format!("Criados com sucesso {} n�s", nodes.len()));
            
            // Aguardar para forma��o da rede
            thread::sleep(Duration::from_secs(3));
            
            // Verificar conex�es
            let connected = nodes[0].get_connected_nodes();
            results.add_detail(&format!("N� seed conectado a {} de {} n�s", connected.len(), nodes.len() - 1));
            
            // Testar broadcast a partir do seed
            let broadcast_data = vec![1, 2, 3, 4];
            let start = Instant::now();
            
            for i in 0..self.message_count {
                match nodes[0].broadcast_message(
                    MessageType::Heartbeat,
                    broadcast_data.clone()
                ) {
                    Ok(count) => {
                        if i == 0 || i == self.message_count - 1 {
                            results.add_detail(&format!("Broadcast {} enviado para {} n�s", i, count));
                        }
                    },
                    Err(e) => {
                        results.add_detail(&format!("Erro no broadcast {}: {}", i, e));
                    }
                }
                
                thread::sleep(Duration::from_millis(50));
            }
            
            let duration = start.elapsed();
            let msgs_per_sec = self.message_count as f64 / duration.as_secs_f64();
            
            results.add_metric(&format!("broadcast_msgs_per_sec_{}_nodes", nodes.len()), msgs_per_sec);
            results.add_detail(&format!(
                "Broadcast em rede de {} n�s: {} msgs em {:?} ({:.2} msgs/s)",
                nodes.len(), self.message_count, duration, msgs_per_sec
            ));
            
            // Limpar
            for node in &nodes {
                let _ = node.stop();
            }
            
            // Pausa entre testes
            thread::sleep(Duration::from_secs(2));
        }
        
        results
    }
}

// Benchmark de descoberta de n�s
struct NodeDiscoveryBenchmark {
    node_count: usize,
    test_duration_secs: u64,
}

impl NodeDiscoveryBenchmark {
    fn new() -> Self {
        Self {
            node_count: 10,
            test_duration_secs: 30,
        }
    }
}

impl P2PBenchmark for NodeDiscoveryBenchmark {
    fn name(&self) -> &str {
        "node_discovery"
    }
    
    fn description(&self) -> &str {
        "Mede a efici�ncia da descoberta de n�s na rede"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        // Criar n�s para teste
        let mut nodes = Vec::with_capacity(self.node_count);
        let seed_port = 8000;
        
        results.add_detail(&format!("Criando {} n�s para teste de descoberta", self.node_count));
        
        // Criar seed node
        let seed_config = P2PConfig {
            node_id: "discovery_seed".to_string(),
            listen_address: format!("127.0.0.1:{}", seed_port),
            seed_nodes: vec![],
            node_cache_path: None,
            max_connections: 100,
            enable_bridges: false,
            trusted_peers: vec![],
        };
        
        match EnhancedP2PNetwork::new(seed_config) {
            Ok(node) => {
                if let Err(e) = node.start() {
                    results.add_detail(&format!("Erro ao iniciar seed node: {}", e));
                    return results;
                }
                nodes.push(node);
            },
            Err(e) => {
                results.add_detail(&format!("Erro ao criar seed node: {}", e));
                return results;
            }
        }
        
        // Criar metade dos n�s conectados diretamente ao seed
        for i in 1..(self.node_count / 2) {
            let config = P2PConfig {
                node_id: format!("discovery_direct_{}", i),
                listen_address: format!("127.0.0.1:{}", seed_port + i),
                seed_nodes: vec![format!("127.0.0.1:{}", seed_port)],
                node_cache_path: None,
                max_connections: 20,
                enable_bridges: false,
                trusted_peers: vec![],
            };
            
            match EnhancedP2PNetwork::new(config) {
                Ok(node) => {
                    if let Err(e) = node.start() {
                        results.add_detail(&format!("Erro ao iniciar n� direto {}: {}", i, e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar n� direto {}: {}", i, e));
                    continue;
                }
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        // Aguardar forma��o inicial da rede
        thread::sleep(Duration::from_secs(3));
        
        // Verificar n�s conhecidos pelo seed
        let known_nodes_before = nodes[0].get_known_nodes();
        results.add_detail(&format!("Seed conhece {} n�s inicialmente", known_nodes_before.len()));
        
        // Criar o restante dos n�s conectados a um dos segundos n�s (n�o ao seed)
        let second_node_port = seed_port + 1;
        
        for i in (self.node_count / 2)..self.node_count {
            let config = P2PConfig {
                node_id: format!("discovery_indirect_{}", i),
                listen_address: format!("127.0.0.1:{}", seed_port + i),
                seed_nodes: vec![format!("127.0.0.1:{}", second_node_port)],
                node_cache_path: None,
                max_connections: 20,
                enable_bridges: false,
                trusted_peers: vec![],
            };
            
            match EnhancedP2PNetwork::new(config) {
                Ok(node) => {
                    if let Err(e) = node.start() {
                        results.add_detail(&format!("Erro ao iniciar n� indireto {}: {}", i, e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar n� indireto {}: {}", i, e));
                    continue;
                }
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        results.add_detail(&format!("Criados com sucesso {} n�s no total", nodes.len()));
        results.add_detail("Aguardando propaga��o da descoberta de n�s...");
        
        // Iniciar contagem de tempo para descoberta
        let start = Instant::now();
        let end_time = start + Duration::from_secs(self.test_duration_secs);
        
        // Coletar dados ao longo do tempo
        let mut discovery_times = Vec::new();
        let mut last_known_count = known_nodes_before.len();
        
        while Instant::now() < end_time {
            let current_known = nodes[0].get_known_nodes();
            
            if current_known.len() > last_known_count {
                let elapsed = start.elapsed().as_secs_f64();
                discovery_times.push((current_known.len(), elapsed));
                
                results.add_detail(&format!(
                    "T+{:.1}s: Seed descobriu {} n�s",
                    elapsed, current_known.len()
                ));
                
                last_known_count = current_known.len();
                
                // Se descobrimos todos os n�s, podemos parar
                if current_known.len() >= nodes.len() {
                    break;
                }
            }
            
            thread::sleep(Duration::from_secs(1));
        }
        
        // Calcular m�tricas finais
        let final_known = nodes[0].get_known_nodes();
        let discovery_ratio = final_known.len() as f64 / nodes.len() as f64;
        let discovery_time = start.elapsed().as_secs_f64();
        
        results.add_metric("discovery_ratio", discovery_ratio * 100.0); // Percentual
        results.add_metric("discovery_time_seconds", discovery_time);
        
        results.add_detail(&format!(
            "\nResultado final: Seed descobriu {} de {} n�s ({:.1}%) em {:.1} segundos",
            final_known.len(), nodes.len(), discovery_ratio * 100.0, discovery_time
        ));
        
        // Se temos pontos de dados suficientes, calcular taxa de descoberta
        if discovery_times.len() >= 2 {
            let first = discovery_times.first().unwrap();
            let last = discovery_times.last().unwrap();
            
            let nodes_per_second = (last.0 - first.0) as f64 / (last.1 - first.1);
            results.add_metric("nodes_discovery_rate", nodes_per_second);
            
            results.add_detail(&format!(
                "Taxa m�dia de descoberta: {:.2} n�s/segundo",
                nodes_per_second
            ));
        }
        
        // Limpar
        for node in &nodes {
            let _ = node.stop();
        }
        
        results
    }
}

// Executor de benchmark
struct BenchmarkRunner {
    benchmarks: Vec<Box<dyn P2PBenchmark>>,
    output_dir: String,
}

impl BenchmarkRunner {
    fn new(output_dir: &str) -> Self {
        Self {
            benchmarks: Vec::new(),
            output_dir: output_dir.to_string(),
        }
    }
    
    fn add_benchmark<T: P2PBenchmark + 'static>(&mut self, benchmark: T) {
        self.benchmarks.push(Box::new(benchmark));
    }
    
    fn run_all(&self) -> Vec<BenchmarkResults> {
        let mut results = Vec::new();
        
        println!("Iniciando suite de benchmarks P2P...");
        
        for benchmark in &self.benchmarks {
            println!("\n=== Executando benchmark: {} ===", benchmark.name());
            println!("Descri��o: {}", benchmark.description());
            
            let start = Instant::now();
            let result = benchmark.run();
            let duration = start.elapsed();
            
            println!("Benchmark conclu�do em {:?}", duration);
            
            // Salvar resultado em arquivo
            if let Err(e) = result.save_to_file(&self.output_dir) {
                println!("Erro ao salvar resultado: {}", e);
            }
            
            // Imprimir resumo
            println!("Resumo:");
            for (metric, value) in &result.metrics {
                println!("  {}: {:.2}", metric, value);
            }
            
            results.push(result);
        }
        
        println!("\nTodos os benchmarks conclu�dos!");
        
        // Gerar relat�rio consolidado
        self.generate_report(&results);
        
        results
    }
    
    fn generate_report(&self, results: &[BenchmarkResults]) {
        let report_path = format!("{}/benchmark_report.md", self.output_dir);
        let mut file = match File::create(&report_path) {
            Ok(f) => f,
            Err(e) => {
                println!("Erro ao criar arquivo de relat�rio: {}", e);
                return;
            }
        };
        
        // Escrever cabe�alho
        let header = format!(
            "# Relat�rio de Benchmark P2P\n\nGerado em: {}\n\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        
        if let Err(e) = file.write_all(header.as_bytes()) {
            println!("Erro ao escrever cabe�alho: {}", e);
            return;
        }
        
        // Escrever resultados de cada benchmark
        for result in results {
            let section = format!(
                "## {}\n\n",
                result.name
            );
            
            if let Err(e) = file.write_all(section.as_bytes()) {
                println!("Erro ao escrever se��o: {}", e);
                continue;
            }
            
            // Tabela de m�tricas
            let mut metrics_table = String::from("| M�trica | Valor |\n|---------|-------|\n");
            
            for (metric, value) in &result.metrics {
                metrics_table.push_str(&format!("| {} | {:.2} |\n", metric, value));
            }
            
            metrics_table.push_str("\n");
            
            if let Err(e) = file.write_all(metrics_table.as_bytes()) {
                println!("Erro ao escrever tabela: {}", e);
                continue;
            }
            
            // Detalhes (opcional)
            if !result.details.is_empty() {
                let details = format!("### Detalhes\n\n```\n{}\n```\n\n", result.details);
                
                if let Err(e) = file.write_all(details.as_bytes()) {
                    println!("Erro ao escrever detalhes: {}", e);
                }
            }
        }
        
        println!("Relat�rio gerado em: {}", report_path);
    }
}

// Fun��o principal para executar todos os benchmarks
pub fn run_p2p_benchmarks(output_dir: &str) {
    // Criar diret�rio de sa�da se n�o existir
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        println!("Erro ao criar diret�rio de sa�da: {}", e);
        return;
    }
    
    // Configurar runner
    let mut runner = BenchmarkRunner::new(output_dir);
    
    // Adicionar benchmarks
    runner.add_benchmark(MessageThroughputBenchmark::new());
    runner.add_benchmark(QuantumCryptoBenchmark::new());
    runner.add_benchmark(NetworkScalabilityBenchmark::new());
    runner.add_benchmark(NodeDiscoveryBenchmark::new());
    
    // Executar todos
    runner.run_all();
}

// Executar com configura��es espec�ficas de ambiente
pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() > 1 {
        &args[1]
    } else {
        "./benchmark_results"
    };
    
    println!("Iniciando benchmarks P2P com sa�da em: {}", output_dir);
    run_p2p_benchmarks(output_dir);
}