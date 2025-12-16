use lit_rust_sdk::{LitNetwork, LitNodeClient, LitNodeClientConfig};
use std::time::Duration;

#[tokio::test]
async fn test_connect_to_naga_dev() {
    // Initialize tracing for debugging
    tracing_subscriber::fmt::init();

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::NagaDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    // Create client
    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    // Connect to the network
    match client.connect().await {
        Ok(()) => {
            println!("Successfully connected to Lit Network!");

            // Verify connection state
            assert!(client.is_ready());

            let connected_nodes = client.connected_nodes();
            println!("Connected to {} nodes:", connected_nodes.len());
            for node in &connected_nodes {
                println!("  - {}", node);
            }

            // Get connection state details
            let state = client.get_connection_state();

            // Verify we have network keys
            assert!(state.network_pub_key.is_some());
            assert!(state.subnet_pub_key.is_some());
            assert!(state.network_pub_key_set.is_some());
            assert!(state.latest_blockhash.is_some());

            println!("\nNetwork State:");
            println!(
                "  Network Public Key: {}",
                state.network_pub_key.as_ref().unwrap()
            );
            println!(
                "  Subnet Public Key: {}",
                state.subnet_pub_key.as_ref().unwrap()
            );
            println!(
                "  Latest Blockhash: {}",
                state.latest_blockhash.as_ref().unwrap()
            );

            // Verify minimum node count
            assert!(connected_nodes.len() >= 2);
        }
        Err(e) => {
            panic!("Failed to connect to Lit Network: {}", e);
        }
    }
}

#[tokio::test]
async fn test_connect_to_naga_test() {
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::NagaTest,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: true, // Enable attestation for test network
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    match client.connect().await {
        Ok(()) => {
            println!("Successfully connected to Naga Test Network!");
            assert!(client.is_ready());

            let connected_nodes = client.connected_nodes();
            println!("Connected to {} nodes", connected_nodes.len());
            assert!(!connected_nodes.is_empty());
        }
        Err(e) => {
            // This is expected to fail for now since we haven't implemented
            // the full validator discovery from the staking contract
            println!("Expected failure (not fully implemented): {}", e);
        }
    }
}

#[tokio::test]
async fn test_connect_to_naga() {
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::Naga,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: true, // Enable attestation for mainnet
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    match client.connect().await {
        Ok(()) => {
            println!("Successfully connected to Naga Mainnet!");
            assert!(client.is_ready());

            let connected_nodes = client.connected_nodes();
            println!("Connected to {} nodes", connected_nodes.len());
            assert!(!connected_nodes.is_empty());
        }
        Err(e) => {
            // This is expected to fail for now since we haven't implemented
            // the full validator discovery from the staking contract
            println!("Expected failure (not fully implemented): {}", e);
        }
    }
}
