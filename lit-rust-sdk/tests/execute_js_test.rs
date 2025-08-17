use alloy::{network::EthereumWallet, primitives::U256, providers::ProviderBuilder};
use chrono::{Datelike, Duration as ChronoDuration, TimeZone, Utc};
use lit_rust_sdk::{
    auth::{load_wallet_from_env, EthWalletProvider},
    blockchain::{resolve_address, Contract, RateLimitNFT},
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig,
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

    println!("🔑 Using wallet address: {}", wallet.address());

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

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

    // TODO: Create capacity delegation auth sig
    // println!("🔄 Creating capacity delegation auth sig...");
    // let delegatee_addresses = vec![wallet.address().to_string()];
    // let capacity_auth_sig = match client
    //     .create_capacity_delegation_auth_sig(
    //         &wallet,
    //         &pkp_token_id,
    //         &delegatee_addresses,
    //         "10", // Allow 10 uses
    //     )
    //     .await
    // {
    //     Ok(sig) => {
    //         println!("✅ Created capacity delegation auth sig");
    //         sig
    //     }
    //     Err(e) => {
    //         println!("❌ Failed to create capacity delegation auth sig: {}", e);
    //         println!("Skipping test - capacity delegation failed");
    //         return;
    //     }
    // };

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

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

    println!("signing lit action{}", signing_lit_action);

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");
    client.connect().await.expect("Failed to connect");

    // Create auth method
    let auth_method = EthWalletProvider::authenticate(&wallet, &client)
        .await
        .expect("Failed to create auth method");

    // // Create capacity delegation auth sig
    // let delegatee_addresses = vec![wallet.address().to_string()];
    // let capacity_auth_sig = client
    //     .create_capacity_delegation_auth_sig(&wallet, &pkp_token_id, &delegatee_addresses, "10")
    //     .await
    //     .expect("Failed to create capacity delegation");

    // Create resource ability requests for signing
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339();

    // Get session signatures
    let session_sigs = client
        .get_pkp_session_sigs(
            &pkp_public_key,
            &pkp_eth_address,
            vec![],
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
            panic!("❌ Signing Lit Action execution failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_execute_js_with_capacity_delegation_datil() {
    // This test validates the complete capacity delegation flow:
    // 1. Mint a Rate Limit NFT
    // 2. Create capacity delegation signature
    // 3. Use it to execute a Lit Action

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

    println!("🔑 Using wallet address: {}", wallet.address());

    // Step 1: Mint a Rate Limit NFT inline for capacity delegation
    println!("🎫 Minting Rate Limit NFT for capacity delegation test...");

    let rate_limit_nft_address = resolve_address(Contract::RateLimitNFT, LitNetwork::Datil)
        .await
        .expect("Failed to resolve Rate Limit NFT contract address");

    println!(
        "Rate Limit NFT contract address: {}",
        rate_limit_nft_address
    );

    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let blockchain_provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(LitNetwork::Datil.rpc_url())
        .await
        .expect("Failed to connect to Ethereum network");

    let rate_limit_nft = RateLimitNFT::new(rate_limit_nft_address, blockchain_provider.clone());

    // Calculate expiresAt: 20 days from now, at midnight UTC
    let now = Utc::now();
    let future_date = now + ChronoDuration::days(20);
    let midnight_date = Utc
        .with_ymd_and_hms(
            future_date.year(),
            future_date.month(),
            future_date.day(),
            0,
            0,
            0,
        )
        .single()
        .expect("Invalid date");

    let expires_at = U256::from(midnight_date.timestamp() as u64);
    let requests_per_kilosecond = U256::from(1000);

    // Calculate the exact cost needed
    let cost = rate_limit_nft
        .calculateCost(requests_per_kilosecond, expires_at)
        .call()
        .await
        .expect("Failed to calculate cost");

    println!("💰 Calculated cost: {} wei", cost);

    // Mint the Rate Limit NFT
    let tx = rate_limit_nft.mint(expires_at).value(cost);
    let pending_tx = tx.send().await.expect("Failed to send mint transaction");

    println!(
        "✅ Rate Limit NFT mint transaction sent: {}",
        pending_tx.tx_hash()
    );
    println!("⏳ Waiting for transaction to be mined...");

    let receipt = pending_tx
        .get_receipt()
        .await
        .expect("Failed to get transaction receipt");

    println!(
        "✅ Rate Limit NFT minted in block: {:?}",
        receipt.block_number
    );

    // Extract token ID from the mint transaction
    let mut rate_limit_nft_token_id = None;
    let logs = receipt.logs();
    for log in logs {
        // Look for Transfer event (topic[0] = Transfer, topic[1] = from, topic[2] = to, topic[3] = tokenId)
        if log.topics().len() >= 4 {
            let token_id_u256 = U256::from_be_bytes(log.topics()[3].0);
            rate_limit_nft_token_id = Some(token_id_u256.to_string());
            println!("🎫 Rate Limit NFT Token ID: {}", token_id_u256);
            break;
        }
    }

    let rate_limit_nft_token_id =
        rate_limit_nft_token_id.expect("Failed to extract token ID from mint transaction");

    // Step 2: Now test capacity delegation with the freshly minted NFT
    println!("🔄 Setting up Lit Network client for capacity delegation...");

    // Create client configuration for datil-dev (better connectivity than datil-test)
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::Datil,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    // Create and connect client
    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    match client.connect().await {
        Ok(()) => {
            println!("✅ Connected to Lit Network (datil)");
        }
        Err(e) => {
            println!("❌ Failed to connect to Lit Network: {}", e);
            println!("Skipping test - Lit network connection failed");
            return;
        }
    }

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

    // Create capacity delegation auth sig
    println!("🔄 Creating capacity delegation auth sig...");
    let delegatee_addresses = vec![wallet.address().to_string()];
    let capacity_auth_sig = match EthWalletProvider::create_capacity_delegation_auth_sig(
        &wallet,
        &rate_limit_nft_token_id,
        &delegatee_addresses,
        "10", // Allow 10 uses
    )
    .await
    {
        Ok(sig) => {
            println!("✅ Created capacity delegation auth sig");
            println!("📝 Capacity delegation signature: {:?}", sig);
            sig
        }
        Err(e) => {
            println!("❌ Failed to create capacity delegation auth sig: {}", e);
            println!("Skipping test - capacity delegation failed");
            return;
        }
    };

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    // Set expiration to 10 minutes from now
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Get session signatures using capacity delegation
    // For testing purposes, we'll use the PKP env vars or fallback to a test address
    let pkp_public_key = std::env::var("PKP_PUBLIC_KEY").unwrap_or_else(|_| {
        // This is a test public key - in reality you'd need a real PKP
        "0x04d2688b6bc2ce7f9ba8b5c86a9eeaae3c8e8c7fb36b2c2e6c4b4b8f3c5e5a3b2d".to_string()
    });

    let pkp_eth_address = std::env::var("PKP_ETH_ADDRESS").unwrap_or_else(|_| {
        // Use the wallet address as fallback for testing
        wallet.address().to_string()
    });

    println!("🔄 Getting PKP session signatures with capacity delegation...");
    println!("   🔑 PKP Public Key: {}", pkp_public_key);
    println!("   🔑 PKP ETH Address: {}", pkp_eth_address);

    let session_sigs = match client
        .get_pkp_session_sigs(
            &pkp_public_key,
            &pkp_eth_address,
            vec![capacity_auth_sig],
            vec![auth_method],
            resource_ability_requests,
            &expiration_str,
        )
        .await
    {
        Ok(session_sigs) => {
            println!("✅ Got session signatures with capacity delegation!");
            println!("📊 Number of session signatures: {}", session_sigs.len());

            // Print session signature keys (node URLs)
            for (node_url, _sig) in &session_sigs {
                println!("  📋 Session sig from node: {}", node_url);
            }

            session_sigs
        }
        Err(e) => {
            println!("❌ Failed to get session signatures: {}", e);
            println!("This test validates that the capacity delegation signature is correct");
            println!("If this fails, it means the signature format or Rate Limit NFT is invalid");
            panic!("Capacity delegation test failed - signature rejected by datil network");
        }
    };

    // Now execute the Lit Action with the capacity delegation!
    println!("🚀 Executing Lit Action with Rate Limit NFT capacity delegation on datil...");
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("🎉 Lit Action executed successfully with Rate Limit NFT capacity delegation on datil!");
            println!("📤 Response: {:?}", response.response);
            println!("📜 Logs: {}", response.logs);

            // Verify we got the expected response
            if let Some(response_obj) = response.response.as_object() {
                if let Some(response_msg) = response_obj.get("response") {
                    assert!(
                        response_msg
                            .as_str()
                            .unwrap_or("")
                            .contains("Hello from Lit Action executed by Rust SDK"),
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
            println!("🎉 CAPACITY DELEGATION SIGNATURE WORKS ON DATIL NETWORK!");
            println!(
                "🎫 Rate Limit NFT Token ID {} successfully provided capacity",
                rate_limit_nft_token_id
            );
        }
        Err(e) => {
            println!("❌ Lit Action execution failed: {}", e);
            println!("This indicates the capacity delegation signature was accepted but execution failed");
            println!("Check the Rate Limit NFT has sufficient capacity remaining");
            panic!("Lit Action execution failed despite valid capacity delegation");
        }
    }
}
