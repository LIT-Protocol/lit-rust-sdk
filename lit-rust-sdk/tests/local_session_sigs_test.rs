use lit_rust_sdk::{
    auth::load_wallet_from_env,
    types::{
        ExecuteJsParams, LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource,
    },
    LitNetwork, LitNodeClient, LitNodeClientConfig,
};
use std::time::Duration;

const HELLO_WORLD_LIT_ACTION: &str = r#"
const go = async () => {
  console.log("Hello from local session sigs!");
  
  // Show that we can execute without a PKP
  const message = "This action was executed with local session signatures, no PKP required!";
  
  Lit.Actions.setResponse({ response: message });
};
go();
"#;

#[tokio::test]
async fn test_local_session_sigs_hello_world() {
    let _ = tracing_subscriber::fmt::try_init();

    dotenv::from_path("../.env").ok();
    dotenv::from_path(".env").ok();

    // Load wallet from environment
    let wallet =
        load_wallet_from_env().expect("Failed to load wallet from ETHEREUM_PRIVATE_KEY env var");

    println!("🔑 Using wallet address: {}", wallet.address());

    // Configure and connect to Lit Network
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    println!("🔄 Connecting to Lit Network...");
    client.connect().await.expect("Failed to connect");
    println!("✅ Connected to {} nodes", client.connected_nodes().len());

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    // Set expiration for session signatures
    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    println!("🔐 Creating local session signatures (no PKP)...");

    // Generate local session signatures without a PKP
    let session_sigs = client
        .get_local_session_sigs(&wallet, resource_ability_requests, &expiration, None)
        .await
        .expect("Failed to create local session signatures");

    println!(
        "✅ Created session signatures for {} nodes",
        session_sigs.len()
    );

    // Execute the Lit Action with local session signatures
    println!("🚀 Executing Lit Action with local session signatures...");

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

    println!("📋 Response: {:?}", response.response);
    println!("📝 Logs: {}", response.logs);

    // For now, just verify the basic execution works
    // The response should be a string for simple use cases
    assert!(response.response.is_string());
    let message = response.response.as_str().unwrap();
    assert_eq!(
        message,
        "This action was executed with local session signatures, no PKP required!"
    );

    println!("✅ Test passed! Successfully executed Lit Action with local session signatures");
}

#[tokio::test]
async fn test_local_session_sigs_with_params() {
    let _ = tracing_subscriber::fmt::try_init();

    dotenv::from_path("../.env").ok();
    dotenv::from_path(".env").ok();

    // Load wallet from environment
    let wallet =
        load_wallet_from_env().expect("Failed to load wallet from ETHEREUM_PRIVATE_KEY env var");

    println!("🔑 Using wallet address: {}", wallet.address());

    // Configure and connect to Lit Network
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    println!("🔄 Connecting to Lit Network...");
    client.connect().await.expect("Failed to connect");
    println!("✅ Connected to {} nodes", client.connected_nodes().len());

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    // Set expiration for session signatures
    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    println!("🔐 Creating local session signatures (no PKP)...");

    // Generate local session signatures without a PKP
    let session_sigs = client
        .get_local_session_sigs(&wallet, resource_ability_requests, &expiration, None)
        .await
        .expect("Failed to create local session signatures");

    println!(
        "✅ Created session signatures for {} nodes",
        session_sigs.len()
    );

    // Lit Action that demonstrates local session signature capabilities
    let lit_action_with_params = r#"
    const go = async () => {
      console.log("Testing local session signatures with different functionality");
      
      // Test various operations available in Lit Actions
      const currentTime = new Date().toISOString();
      console.log(`Current time: ${currentTime}`);
      
      // Demonstrate that we can do computations
      const computation = 42 * 2 + 10;
      console.log(`Computation result: ${computation}`);
      
      Lit.Actions.setResponse({ 
        response: `Lit Action executed successfully at ${currentTime} with result: ${computation}`,
      });
    };
    go();
    "#;

    // Execute the Lit Action
    println!("🚀 Executing Lit Action with local session signatures...");

    let execute_params = ExecuteJsParams {
        code: Some(lit_action_with_params.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    let response = client
        .execute_js(execute_params)
        .await
        .expect("Failed to execute Lit Action");

    println!("📋 Response: {:?}", response.response);
    println!("📝 Logs: {}", response.logs);

    // Verify the basic execution works
    // The response should be a string containing our computation result
    assert!(response.response.is_string());
    let message = response.response.as_str().unwrap();
    assert!(message.contains("Lit Action executed successfully"));
    assert!(message.contains("94")); // Our computation result: 42 * 2 + 10 = 94

    println!("✅ Test passed! Successfully executed Lit Action with local session signatures and additional functionality");
}
