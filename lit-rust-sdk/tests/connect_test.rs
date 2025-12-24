use lit_rust_sdk::{create_lit_client, naga_dev, naga_test};
use std::env;

fn get_rpc_url() -> Option<String> {
    env::var("LIT_RPC_URL")
        .or_else(|_| env::var("LIT_TXSENDER_RPC_URL"))
        .or_else(|_| env::var("LIT_YELLOWSTONE_PRIVATE_RPC_URL"))
        .or_else(|_| env::var("LOCAL_RPC_URL"))
        .ok()
}

#[tokio::test]
async fn test_connect_to_naga_dev() {
    let _ = dotenvy::dotenv();

    let rpc_url = match get_rpc_url() {
        Some(url) => url,
        None => {
            println!("Skipping test - no RPC URL configured");
            println!("Set LIT_RPC_URL or LIT_TXSENDER_RPC_URL in .env");
            return;
        }
    };

    let config = naga_dev().with_rpc_url(rpc_url);

    match create_lit_client(config).await {
        Ok(client) => {
            println!("Successfully connected to Naga Dev Network!");

            // Verify handshake data is available
            let handshake = client.handshake_result();

            assert!(
                !handshake.connected_nodes.is_empty(),
                "Should be connected to at least one node"
            );
            println!("Connected to {} nodes:", handshake.connected_nodes.len());
            for node in &handshake.connected_nodes {
                println!("  - {}", node);
            }

            // Verify we have network keys
            assert!(
                !handshake.core_node_config.subnet_pub_key.is_empty(),
                "Should have subnet public key"
            );
            assert!(
                !handshake.core_node_config.network_pub_key.is_empty(),
                "Should have network public key"
            );
            assert!(
                !handshake.core_node_config.latest_blockhash.is_empty(),
                "Should have latest blockhash"
            );

            println!("\nNetwork State:");
            println!(
                "  Network Public Key: {}",
                &handshake.core_node_config.network_pub_key
                    [..40.min(handshake.core_node_config.network_pub_key.len())]
            );
            println!(
                "  Subnet Public Key: {}",
                &handshake.core_node_config.subnet_pub_key
                    [..40.min(handshake.core_node_config.subnet_pub_key.len())]
            );
            println!(
                "  Latest Blockhash: {}",
                handshake.core_node_config.latest_blockhash
            );
            println!("  Epoch: {}", handshake.epoch);
            println!("  Threshold: {}", handshake.threshold);

            // Verify minimum node count (threshold)
            assert!(
                handshake.connected_nodes.len() >= handshake.threshold,
                "Should have at least threshold nodes connected"
            );

            println!("Test passed!");
        }
        Err(e) => {
            panic!("Failed to connect to Naga Dev Network: {}", e);
        }
    }
}

#[tokio::test]
async fn test_connect_to_naga_test() {
    let _ = dotenvy::dotenv();

    let rpc_url = match get_rpc_url() {
        Some(url) => url,
        None => {
            println!("Skipping test - no RPC URL configured");
            return;
        }
    };

    let config = naga_test().with_rpc_url(rpc_url);

    match create_lit_client(config).await {
        Ok(client) => {
            println!("Successfully connected to Naga Test Network!");

            let handshake = client.handshake_result();
            println!("Connected to {} nodes", handshake.connected_nodes.len());

            assert!(
                !handshake.connected_nodes.is_empty(),
                "Should be connected to at least one node"
            );
        }
        Err(e) => {
            // This might fail if the test network is not available
            println!("Failed to connect to Naga Test Network: {}", e);
            println!("This may be expected if naga-test network is not available");
        }
    }
}
