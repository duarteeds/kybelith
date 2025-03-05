use kybelith::p2p::message::Message;
use kybelith::p2p::MessageType;
use kybelith::p2p::network::SecureNetworkManager;

#[test]
fn test_network_manager() {
    // Use dynamic port with "127.0.0.1:0"
    let network = SecureNetworkManager::new(
        "127.0.0.1:0",
        "local_node_id".to_string(),
        vec![1, 2, 3], // Dummy public key
    )
    .expect("Falha ao inicializar NetworkManager");

    // Start the network to ensure listener is active
    network.start().expect("Failed to start NetworkManager");

    // Create a test message
    let message = Message {
        sender: "local_node_id".to_string(),
        message_type: MessageType::Handshake,
        payload: vec![1, 2, 3],
    };

    // Broadcast the message
    let result = network.broadcast_message(message);
    assert!(result.is_ok(), "Broadcast failed: {:?}", result.err());

    // Print the bound port for debugging
    println!("NetworkManager bound to port: {}", network.local_port());

    // Test passes if we reach here without panics
    assert!(true);
}

#[test]
fn test_network_manager_creation() {
    // Create a test public key
    let public_key = vec![0u8; 32]; // Simplified test key

    // Use dynamic port with "127.0.0.1:0"
    let network = SecureNetworkManager::new(
        "127.0.0.1:0",
        "local_node_id".to_string(),
        public_key,
    );

    // Verify creation succeeded
    assert!(network.is_ok(), "Network creation failed: {:?}", network.err());

    // Test basic functionality
    if let Ok(net) = network {
        assert_eq!(net.local_id(), "local_node_id");
        assert_eq!(net.get_connection_count(), 0);
        println!("NetworkManager bound to port: {}", net.local_port());
    }
}

#[test]
fn test_propagate_proposal() {
    // Create a test public key
    let public_key = vec![0u8; 32]; // Example public key for test

    // Use dynamic port with "127.0.0.1:0"
    let network = SecureNetworkManager::new(
        "127.0.0.1:0",
        "local_node_id".to_string(),
        public_key,
    )
    .expect("Falha ao inicializar NetworkManager");

    // Start the network to ensure listener is active
    network.start().expect("Failed to start NetworkManager");

    // Simulate a block proposal message
    let message = Message {
        sender: "local_node_id".to_string(),
        message_type: MessageType::BlockProposal,
        payload: vec![4, 5, 6],
    };

    // Broadcast the proposal
    let result = network.broadcast_message(message);
    assert!(result.is_ok(), "Propagation failed: {:?}", result.err());

    // Verify local ID
    assert_eq!(network.local_id(), "local_node_id");

    // Print the bound port for debugging
    println!("NetworkManager bound to port: {}", network.local_port());
}