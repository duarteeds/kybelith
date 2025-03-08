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
        results.add_detail(&format!("Execução: {} iterações por tamanho", self.iterations));
        
        // Configurar nós
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
                results.add_detail(&format!("Erro ao criar nó 1: {}", e));
                return results;
            }
        };
        
        let node2 = match EnhancedP2PNetwork::new(node2_config) {
            Ok(n) => n,
            Err(e) => {
                results.add_detail(&format!("Erro ao criar nó 2: {}", e));
                return results;
            }
        };
        
        // Iniciar nós
        if let Err(e) = node1.start() {
            results.add_detail(&format!("Erro ao iniciar nó 1: {}", e));
            return results;
        }
        
        if let Err(e) = node2.start() {
            results.add_detail(&format!("Erro ao iniciar nó 2: {}", e));
            node1.stop().unwrap();
            return results;
        }
        
        // Aguardar conexão
        thread::sleep(Duration::from_secs(3));
        results.add_detail("Nós iniciados e conectados");
        
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
                        results.add_detail(&format!("Erro na iteração {}: {}", i, e));
                    }
                }
                
                // Pequena pausa
                thread::sleep(Duration::from_millis(10));
            }
            
            let duration = start.elapsed();
            let throughput_bytes_per_sec = (size * success_count) as f64 / duration.as_secs_f64();
            let throughput_kb_per_sec = throughput_bytes_per_sec / 1024.0;
            let throughput_msgs_per_sec = success_count as f64 / duration.as_secs_f64();
            
            // Adicionar métricas
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
        
        // Calcular média geral
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

// Benchmark para criptografia pós-quântica
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
        "Mede a performance da criptografia pós-quântica (Kyber e Dilithium)"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        // Inicializar os algoritmos criptográficos
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
        results.add_detail(&format!("Executando benchmark Kyber com {} iterações", self.kyber_iterations));
        
        let start = Instant::now();
        
        for i in 0..self.kyber_iterations {
            // Gerar par de chaves
            let keypair_result = kyber.keypair();
            if let Err(e) = keypair_result {
                results.add_detail(&format!("Erro na geração de chaves Kyber (iteração {}): {}", i, e));
                continue;
            }
            
            let (pub_key, _priv_key) = keypair_result.unwrap();
            
            // Encapsular segredo compartilhado
            let encap_result = kyber.encapsulate(&pub_key);
            if let Err(e) = encap_result {
                results.add_detail(&format!("Erro na encapsulação Kyber (iteração {}): {}", i, e));
                continue;
            }
        }
        
        let kyber_duration = start.elapsed();
        let kyber_ops_per_sec = self.kyber_iterations as f64 / kyber_duration.as_secs_f64();
        
        results.add_metric("kyber_ops_per_sec", kyber_ops_per_sec);
        results.add_detail(&format!(
            "Kyber: {} operações em {:?} ({:.2} ops/s)",
            self.kyber_iterations, kyber_duration, kyber_ops_per_sec
        ));
        
        // 2. Benchmark Dilithium (assinaturas)
        results.add_detail(&format!("Executando benchmark Dilithium com {} iterações", self.dilithium_iterations));
        
        // Gerar par de chaves uma vez (parte mais lenta)
        let keypair_result = dilithium.keypair();
        if let Err(e) = keypair_result {
            results.add_detail(&format!("Erro na geração de chaves Dilithium: {}", e));
            return results;
        }
        
        let (pub_key, priv_key) = keypair_result.unwrap();
        
        // Medir separadamente assinatura e verificação
        let start_sign = Instant::now();
        let mut signatures = Vec::with_capacity(self.dilithium_iterations);
        let test_data = b"Test data for signature benchmarking";
        
        for i in 0..self.dilithium_iterations {
            let sign_result = dilithium.sign(test_data, &priv_key);
            
            if let Err(e) = sign_result {
                results.add_detail(&format!("Erro na assinatura Dilithium (iteração {}): {}", i, e));
                continue;
            }
            
            signatures.push(sign_result.unwrap());
        }
        
        let sign_duration = start_sign.elapsed();
        let sign_ops_per_sec = self.dilithium_iterations as f64 / sign_duration.as_secs_f64();
        
        results.add_metric("dilithium_sign_ops_per_sec", sign_ops_per_sec);
        results.add_detail(&format!(
            "Dilithium (assinatura): {} operações em {:?} ({:.2} ops/s)",
            self.dilithium_iterations, sign_duration, sign_ops_per_sec
        ));
        
        // Medir verificação
        let start_verify = Instant::now();
        let mut verify_success = 0;
        
        for (i, signature) in signatures.iter().enumerate() {
            let verify_result = dilithium.verify(test_data, signature, &pub_key);
            
            match verify_result {
                Ok(true) => verify_success += 1,
                Ok(false) => results.add_detail(&format!("Verificação falhou (iteração {})", i)),
                Err(e) => results.add_detail(&format!("Erro na verificação (iteração {}): {}", i, e)),
            }
        }
        
        let verify_duration = start_verify.elapsed();
        let verify_ops_per_sec = signatures.len() as f64 / verify_duration.as_secs_f64();
        
        results.add_metric("dilithium_verify_ops_per_sec", verify_ops_per_sec);
        results.add_detail(&format!(
            "Dilithium (verificação): {} operações em {:?} ({:.2} ops/s)",
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
        "Mede a escalabilidade da rede P2P com diferentes números de nós"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        for &node_count in &self.node_counts {
            results.add_detail(&format!("\nTestando rede com {} nós", node_count));
            
            // Criar nós
            let mut nodes = Vec::with_capacity(node_count);
            let seed_port = 7700;
            
            // Criar primeiro nó (seed)
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
                        results.add_detail(&format!("Erro ao iniciar nó seed: {}", e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar nó seed: {}", e));
                    continue;
                }
            }
            
            // Criar os outros nós
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
                            results.add_detail(&format!("Erro ao iniciar nó {}: {}", i, e));
                            continue;
                        }
                        nodes.push(node);
                    },
                    Err(e) => {
                        results.add_detail(&format!("Erro ao criar nó {}: {}", i, e));
                        continue;
                    }
                }
                
                // Pequena pausa para não sobrecarregar
                thread::sleep(Duration::from_millis(100));
            }
            
            results.add_detail(&format!("Criados com sucesso {} nós", nodes.len()));
            
            // Aguardar para formação da rede
            thread::sleep(Duration::from_secs(3));
            
            // Verificar conexões
            let connected = nodes[0].get_connected_nodes();
            results.add_detail(&format!("Nó seed conectado a {} de {} nós", connected.len(), nodes.len() - 1));
            
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
                            results.add_detail(&format!("Broadcast {} enviado para {} nós", i, count));
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
                "Broadcast em rede de {} nós: {} msgs em {:?} ({:.2} msgs/s)",
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

// Benchmark de descoberta de nós
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
        "Mede a eficiência da descoberta de nós na rede"
    }
    
    fn run(&self) -> BenchmarkResults {
        let mut results = BenchmarkResults::new(self.name());
        
        // Criar nós para teste
        let mut nodes = Vec::with_capacity(self.node_count);
        let seed_port = 8000;
        
        results.add_detail(&format!("Criando {} nós para teste de descoberta", self.node_count));
        
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
        
        // Criar metade dos nós conectados diretamente ao seed
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
                        results.add_detail(&format!("Erro ao iniciar nó direto {}: {}", i, e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar nó direto {}: {}", i, e));
                    continue;
                }
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        // Aguardar formação inicial da rede
        thread::sleep(Duration::from_secs(3));
        
        // Verificar nós conhecidos pelo seed
        let known_nodes_before = nodes[0].get_known_nodes();
        results.add_detail(&format!("Seed conhece {} nós inicialmente", known_nodes_before.len()));
        
        // Criar o restante dos nós conectados a um dos segundos nós (não ao seed)
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
                        results.add_detail(&format!("Erro ao iniciar nó indireto {}: {}", i, e));
                        continue;
                    }
                    nodes.push(node);
                },
                Err(e) => {
                    results.add_detail(&format!("Erro ao criar nó indireto {}: {}", i, e));
                    continue;
                }
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        results.add_detail(&format!("Criados com sucesso {} nós no total", nodes.len()));
        results.add_detail("Aguardando propagação da descoberta de nós...");
        
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
                    "T+{:.1}s: Seed descobriu {} nós",
                    elapsed, current_known.len()
                ));
                
                last_known_count = current_known.len();
                
                // Se descobrimos todos os nós, podemos parar
                if current_known.len() >= nodes.len() {
                    break;
                }
            }
            
            thread::sleep(Duration::from_secs(1));
        }
        
        // Calcular métricas finais
        let final_known = nodes[0].get_known_nodes();
        let discovery_ratio = final_known.len() as f64 / nodes.len() as f64;
        let discovery_time = start.elapsed().as_secs_f64();
        
        results.add_metric("discovery_ratio", discovery_ratio * 100.0); // Percentual
        results.add_metric("discovery_time_seconds", discovery_time);
        
        results.add_detail(&format!(
            "\nResultado final: Seed descobriu {} de {} nós ({:.1}%) em {:.1} segundos",
            final_known.len(), nodes.len(), discovery_ratio * 100.0, discovery_time
        ));
        
        // Se temos pontos de dados suficientes, calcular taxa de descoberta
        if discovery_times.len() >= 2 {
            let first = discovery_times.first().unwrap();
            let last = discovery_times.last().unwrap();
            
            let nodes_per_second = (last.0 - first.0) as f64 / (last.1 - first.1);
            results.add_metric("nodes_discovery_rate", nodes_per_second);
            
            results.add_detail(&format!(
                "Taxa média de descoberta: {:.2} nós/segundo",
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
            println!("Descrição: {}", benchmark.description());
            
            let start = Instant::now();
            let result = benchmark.run();
            let duration = start.elapsed();
            
            println!("Benchmark concluído em {:?}", duration);
            
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
        
        println!("\nTodos os benchmarks concluídos!");
        
        // Gerar relatório consolidado
        self.generate_report(&results);
        
        results
    }
    
    fn generate_report(&self, results: &[BenchmarkResults]) {
        let report_path = format!("{}/benchmark_report.md", self.output_dir);
        let mut file = match File::create(&report_path) {
            Ok(f) => f,
            Err(e) => {
                println!("Erro ao criar arquivo de relatório: {}", e);
                return;
            }
        };
        
        // Escrever cabeçalho
        let header = format!(
            "# Relatório de Benchmark P2P\n\nGerado em: {}\n\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        
        if let Err(e) = file.write_all(header.as_bytes()) {
            println!("Erro ao escrever cabeçalho: {}", e);
            return;
        }
        
        // Escrever resultados de cada benchmark
        for result in results {
            let section = format!(
                "## {}\n\n",
                result.name
            );
            
            if let Err(e) = file.write_all(section.as_bytes()) {
                println!("Erro ao escrever seção: {}", e);
                continue;
            }
            
            // Tabela de métricas
            let mut metrics_table = String::from("| Métrica | Valor |\n|---------|-------|\n");
            
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
        
        println!("Relatório gerado em: {}", report_path);
    }
}

// Função principal para executar todos os benchmarks
pub fn run_p2p_benchmarks(output_dir: &str) {
    // Criar diretório de saída se não existir
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        println!("Erro ao criar diretório de saída: {}", e);
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

// Executar com configurações específicas de ambiente
pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = if args.len() > 1 {
        &args[1]
    } else {
        "./benchmark_results"
    };
    
    println!("Iniciando benchmarks P2P com saída em: {}", output_dir);
    run_p2p_benchmarks(output_dir);
}