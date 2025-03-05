use sha3::{Sha3_256, Digest};
use rand::{thread_rng, RngCore};

/// Implementa um hash resistente a ataques quânticos usando SHA-3 com salt
/// 
/// Esta função aplica SHA-3 duas vezes com um salt aleatório entre eles
/// para aumentar a resistência contra ataques de Grover em computadores quânticos.
pub fn quantum_resistant_hash(data: &[u8]) -> Vec<u8> {
    // SHA-3 (Keccak) é considerado resistente a ataques quânticos
    // Para segurança adicional, podemos aumentar o tamanho da saída
    let hash1 = Sha3_256::digest(data);
    
    // Adicionar salt e realizar segundo hash para maior resistência
    // (técnica semelhante à usada em PBKDF2)
    let mut salted_data = Vec::with_capacity(hash1.len() + 16);
    salted_data.extend_from_slice(&hash1);
    
    // Adicionar um salt aleatório ou derivado
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    salted_data.extend_from_slice(&salt);
    
    // Hash final
    let hash_final = Sha3_256::digest(&salted_data);
    hash_final.to_vec()
}

/// Implementa um hash resistente a quânticos com salt determinístico
/// 
/// Útil quando precisamos obter resultados consistentes com o mesmo input
pub fn deterministic_quantum_hash(data: &[u8], domain_separator: &[u8]) -> Vec<u8> {
    // Primeira passagem com SHA-3
    let mut hash_context = Sha3_256::new();
    hash_context.update(domain_separator);
    hash_context.update(data);
    let hash1 = hash_context.finalize();
    
    // Segunda passagem com domínio diferente
    let mut hash_context = Sha3_256::new();
    hash_context.update(b"FINAL");
    hash_context.update(hash1);
    
    hash_context.finalize().to_vec()
}

/// Verifica se dois conjuntos de dados produzem o mesmo hash
pub fn verify_quantum_hash(data: &[u8], expected_hash: &[u8], domain_separator: &[u8]) -> bool {
    let computed_hash = deterministic_quantum_hash(data, domain_separator);
    constant_time_eq(&computed_hash, expected_hash)
}

/// Compara dois slices em tempo constante para evitar ataques de timing
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}