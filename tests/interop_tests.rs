#[cfg(test)]
mod tests {
    use kybelith::p2p::interop::protocol::{verify_transaction_proof, generate_transaction_proof, convert_address};
    use kybelith::p2p::interop::bridge::BlockchainProtocol;

    #[test]
    fn test_transaction_proof() {
        let tx_id = "tx_12345";
        let block_id = "block_6789";
        
        // Gerar uma prova
        let proof = generate_transaction_proof(tx_id, block_id, &BlockchainProtocol::Kybelith)
            .expect("Falha ao gerar prova");
        
        // Verificar a prova
        let is_valid = verify_transaction_proof(tx_id, &proof, &BlockchainProtocol::Kybelith)
            .expect("Falha ao verificar prova");
        
        assert!(is_valid, "A prova deve ser válida");
    }

    #[test]
    fn test_address_conversion() {
        let eth_address = "0xabcdef1234567890";
        
        // Converter endereço de Ethereum para Kybelith
        let kyb_address = convert_address(eth_address, &BlockchainProtocol::Ethereum, &BlockchainProtocol::Kybelith)
            .expect("Falha ao converter endereço");
        
        // Verificar conversão de volta
        let converted_back = convert_address(&kyb_address, &BlockchainProtocol::Kybelith, &BlockchainProtocol::Ethereum)
            .expect("Falha ao converter endereço de volta");
        
        assert_eq!(eth_address, converted_back, "Conversão de endereços deve ser reversível");
    }
}