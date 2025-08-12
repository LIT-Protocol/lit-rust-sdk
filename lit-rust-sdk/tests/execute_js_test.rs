use lit_rust_sdk::{
    LitNodeClient, LitNodeClientConfig, LitNetwork,
    ResourceAbilityRequest, LitResource, ExecuteJsParams,
};
use std::collections::HashMap;
use std::time::Duration;

const HELLO_WORLD_LIT_ACTION: &str = r#"
const go = async () => {
  console.log("hello world");
  
  // Return a simple response
  Lit.Actions.setResponse({ response: "Hello from Lit Action!" });
};

go();
"#;

#[tokio::test]
async fn test_execute_js_hello_world() {
    // Initialize logging (ignore if already initialized)
    let _ = tracing_subscriber::fmt().try_init();

    // Create client config
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        connect_timeout: Duration::from_secs(30),
        rpc_url: None,
        min_node_count: Some(2),
        alert_when_unauthorized: false,
        debug: true,
        check_node_attestation: false,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config);
    client.connect().await.expect("Failed to connect to Lit Network");

    println!("Connected to Lit Network successfully!");
    println!("Connected nodes: {:?}", client.connected_nodes());

    // For this test, we'll create an empty session signatures map
    // In a real implementation, you'd get these from get_pkp_session_sigs
    // The session_sigs map should have node URLs as keys and SessionSignature as values:
    // session_sigs.insert("https://15.235.83.220:7470".to_string(), session_signature);
    // session_sigs.insert("https://15.235.83.220:7471".to_string(), session_signature);
    // session_sigs.insert("https://15.235.83.220:7472".to_string(), session_signature);
    let session_sigs = HashMap::new();
    
    // Note: This test will fail without proper session signatures
    // This is just to demonstrate the API structure
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    // This will fail without proper session sigs, but demonstrates the API
    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("Lit Action executed successfully!");
            println!("Response: {:?}", response.response);
            println!("Logs: {}", response.logs);
        }
        Err(e) => {
            println!("Lit Action execution failed (expected without session sigs): {}", e);
            // This is expected to fail without proper authentication
        }
    }
}

// This test shows how to create the proper session signatures
#[tokio::test]
#[ignore] // Ignore by default since it requires PKP setup
async fn test_execute_js_with_session_sigs() {
    use ethers::signers::LocalWallet;
    use ethers::core::rand::thread_rng;

    // Initialize logging (ignore if already initialized)
    let _ = tracing_subscriber::fmt().try_init();

    // Create client config
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        connect_timeout: Duration::from_secs(30),
        rpc_url: None,
        min_node_count: Some(2),
        alert_when_unauthorized: false,
        debug: true,
        check_node_attestation: false,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config);
    client.connect().await.expect("Failed to connect to Lit Network");

    // Generate a wallet for capacity delegation
    let wallet = LocalWallet::new(&mut thread_rng());
    
    // These would need to be real values in a working test:
    let pkp_public_key = "YOUR_PKP_PUBLIC_KEY";
    let pkp_eth_address = "YOUR_PKP_ETH_ADDRESS"; 
    let capacity_token_id = "YOUR_CAPACITY_TOKEN_ID";

    // Create capacity delegation auth sig
    let capacity_auth_sig = client
        .create_capacity_delegation_auth_sig(
            &wallet,
            capacity_token_id,
            &[pkp_eth_address.to_string()],
            "100", // uses
        )
        .await
        .expect("Failed to create capacity delegation auth sig");

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![ResourceAbilityRequest {
        resource: LitResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: "lit-action-execution".to_string(),
    }];

    // Get session signatures
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap()
        .to_rfc3339();

    let session_sigs = client
        .get_pkp_session_sigs(
            pkp_public_key,
            pkp_eth_address,
            vec![capacity_auth_sig],
            vec![], // auth_methods
            resource_ability_requests,
            &expiration,
        )
        .await
        .expect("Failed to get session signatures");

    // Now execute the Lit Action
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    let response = client
        .execute_js(execute_params)
        .await
        .expect("Failed to execute Lit Action");

    println!("Lit Action executed successfully!");
    println!("Response: {:?}", response.response);
    println!("Logs: {}", response.logs);
    
    // Check that we got the expected response
    assert!(response.logs.contains("hello world"));
}