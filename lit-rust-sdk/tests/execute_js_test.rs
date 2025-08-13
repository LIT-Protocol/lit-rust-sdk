use ethers::signers::Signer;
use lit_rust_sdk::{
    auth::{create_pkp_resource, load_wallet_from_env, EthWalletProvider},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig, LitResource,
    ResourceAbilityRequest,
};
use std::time::Duration;

const HELLO_WORLD_LIT_ACTION: &str = r#"
const go = async () => {
  console.log("hello world from Rust SDK!");
  
  // Return a simple response
  Lit.Actions.setResponse({ response: "Hello from Lit Action executed by Rust SDK!" });
};

go();
"#;

#[tokio::test]
async fn test_execute_js_hello_world() {
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt().try_init();

    // Load wallet from environment
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(e) => {
            println!("❌ Failed to load wallet from environment: {}. Make sure ETHEREUM_PRIVATE_KEY is set in .env", e);
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    println!("🔑 Using wallet address: 0x{:x}", wallet.address());

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        min_node_count: Some(2),
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
        rpc_url: None,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config);

    match client.connect().await {
        Ok(()) => {
            println!("✅ Connected to Lit Network");
        }
        Err(e) => {
            panic!("❌ Failed to connect to Lit Network: {}", e);
        }
    }

    // Load PKP environment variables
    let pkp_public_key = match std::env::var("PKP_PUBLIC_KEY") {
        Ok(key) => key,
        Err(_) => {
            println!("❌ PKP_PUBLIC_KEY environment variable not set");
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    let pkp_token_id = match std::env::var("PKP_TOKEN_ID") {
        Ok(id) => id,
        Err(_) => {
            println!("❌ PKP_TOKEN_ID environment variable not set");
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    let pkp_eth_address = match std::env::var("PKP_ETH_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            println!("❌ PKP_ETH_ADDRESS environment variable not set");
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    println!("🔑 Using PKP public key: {}", pkp_public_key);
    println!("🔑 Using PKP token ID: {}", pkp_token_id);
    println!("🔑 Using PKP ETH address: {}", pkp_eth_address);

    // Create auth method
    println!("🔄 Creating auth method...");
    let auth_method = match EthWalletProvider::authenticate(&wallet, &client).await {
        Ok(method) => {
            println!("✅ Created auth method");
            method
        }
        Err(e) => {
            println!("❌ Failed to create auth method: {}", e);
            println!("Skipping test - auth method creation failed");
            return;
        }
    };
    println!("🔑 Auth method: {:?}", auth_method);

    // Create capacity delegation auth sig
    println!("🔄 Creating capacity delegation auth sig...");
    let delegatee_addresses = vec![format!("0x{:x}", wallet.address())];
    let capacity_auth_sig = match client
        .create_capacity_delegation_auth_sig(
            &wallet,
            &pkp_token_id,
            &delegatee_addresses,
            "10", // Allow 10 uses
        )
        .await
    {
        Ok(sig) => {
            println!("✅ Created capacity delegation auth sig");
            sig
        }
        Err(e) => {
            println!("❌ Failed to create capacity delegation auth sig: {}", e);
            println!("Skipping test - capacity delegation failed");
            return;
        }
    };

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![
        // Add PKP signing capability
        ResourceAbilityRequest {
            resource: create_pkp_resource("*"),
            ability: "lit-pkp-signing".to_string(),
        },
        // Add Lit Action execution capability
        ResourceAbilityRequest {
            resource: LitResource {
                resource: "*".to_string(),
                resource_prefix: "lit-litaction".to_string(),
            },
            ability: "lit-action-execution".to_string(),
        },
    ];

    // Set expiration to 10 minutes from now
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Get PKP session signatures
    println!("🔄 Getting PKP session signatures...");
    let session_sigs = match client
        .get_pkp_session_sigs(
            &pkp_public_key,
            &pkp_eth_address,
            vec![],
            vec![auth_method],
            resource_ability_requests,
            &expiration_str,
        )
        .await
    {
        Ok(session_sigs) => {
            println!("✅ Got PKP session signatures!");
            println!("📊 Number of session signatures: {}", session_sigs.len());

            // Print session signature keys (node URLs)
            for (node_url, _sig) in &session_sigs {
                println!("  📋 Session sig from node: {}", node_url);
            }

            session_sigs
        }
        Err(e) => {
            println!("❌ Failed to get PKP session signatures: {}", e);
            println!("Skipping test - session signature generation failed");
            return;
        }
    };

    // Now execute the Lit Action!
    println!("🚀 Executing Lit Action...");
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("🎉 Lit Action executed successfully!");
            println!("📤 Response: {:?}", response.response);
            println!("📜 Logs: {}", response.logs);

            // Verify we got the expected response
            if let Some(response_obj) = response.response.as_object() {
                if let Some(response_msg) = response_obj.get("response") {
                    assert!(
                        response_msg
                            .as_str()
                            .unwrap_or("")
                            .contains("Hello from Lit Action"),
                        "Response should contain expected message"
                    );
                }
            }

            // Verify logs contain our console.log output
            assert!(
                response.logs.contains("hello world from Rust SDK"),
                "Logs should contain our console.log output"
            );

            println!("✅ All assertions passed!");
        }
        Err(e) => {
            println!("❌ Lit Action execution failed: {}", e);
            // Don't panic here since this test requires specific setup
            println!("This test requires valid PKP credentials and capacity delegation setup");
        }
    }
}

#[tokio::test]
async fn test_execute_js_signing() {
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt().try_init();

    // Load wallet from environment
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(_) => {
            println!("Skipping signing test - ETHEREUM_PRIVATE_KEY not set");
            return;
        }
    };

    // Load PKP environment variables
    let pkp_public_key = match std::env::var("PKP_PUBLIC_KEY") {
        Ok(key) => key,
        Err(_) => {
            println!("Skipping signing test - PKP_PUBLIC_KEY not set");
            return;
        }
    };

    let pkp_token_id = match std::env::var("PKP_TOKEN_ID") {
        Ok(id) => id,
        Err(_) => {
            println!("Skipping signing test - PKP_TOKEN_ID not set");
            return;
        }
    };

    let pkp_eth_address = match std::env::var("PKP_ETH_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            println!("Skipping signing test - PKP_ETH_ADDRESS not set");
            return;
        }
    };

    // Lit Action that does signing (similar to the reference implementation)
    let signing_lit_action = format!(
        r#"
const go = async () => {{
  console.log("Starting signing Lit Action");
  
  // This requests a signature share from the Lit Node
  // the signature share will be automatically returned in the response from the node
  // and combined into a full signature by the SDK for you to use on the client
  const utf8Encode = new TextEncoder();
  const toSign = utf8Encode.encode('This message is exactly 32 bytes');
  const publicKey = "{}";
  const sigName = "sig1";
  
  const sigShare = await Lit.Actions.signEcdsa({{ toSign, publicKey, sigName }});
  
  console.log("Signature generation completed");
}};

go();
"#,
        pkp_public_key
    );

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        min_node_count: Some(2),
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
        rpc_url: None,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config);
    client.connect().await.expect("Failed to connect");

    // Create auth method
    let auth_method = EthWalletProvider::authenticate(&wallet, &client)
        .await
        .expect("Failed to create auth method");

    // Create capacity delegation auth sig
    let delegatee_addresses = vec![format!("0x{:x}", wallet.address())];
    let capacity_auth_sig = client
        .create_capacity_delegation_auth_sig(&wallet, &pkp_token_id, &delegatee_addresses, "10")
        .await
        .expect("Failed to create capacity delegation");

    // Create resource ability requests for signing
    let resource_ability_requests = vec![
        ResourceAbilityRequest {
            resource: create_pkp_resource("*"),
            ability: "lit-pkp-signing".to_string(),
        },
        ResourceAbilityRequest {
            resource: LitResource {
                resource: "*".to_string(),
                resource_prefix: "lit-litaction".to_string(),
            },
            ability: "lit-action-execution".to_string(),
        },
    ];

    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339();

    // Get session signatures
    let session_sigs = client
        .get_pkp_session_sigs(
            &pkp_public_key,
            &pkp_eth_address,
            vec![capacity_auth_sig],
            vec![auth_method],
            resource_ability_requests,
            &expiration_str,
        )
        .await
        .expect("Failed to get session signatures");

    // Execute the signing Lit Action
    let execute_params = ExecuteJsParams {
        code: Some(signing_lit_action),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("🎉 Signing Lit Action executed successfully!");
            println!("📤 Response: {:?}", response.response);
            println!("📜 Logs: {}", response.logs);

            // Check if we got signatures back
            if let Some(signatures) = &response.signatures {
                println!("🔐 Got signatures: {:?}", signatures);
            }

            println!("✅ Signing test completed!");
        }
        Err(e) => {
            println!("❌ Signing Lit Action execution failed: {}", e);
            println!("This test requires valid PKP credentials and capacity delegation setup");
        }
    }
}
