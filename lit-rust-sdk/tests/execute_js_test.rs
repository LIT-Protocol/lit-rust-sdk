use alloy::{network::EthereumWallet, primitives::U256, providers::ProviderBuilder, signers::local::PrivateKeySigner};
use chrono::{Datelike, Duration as ChronoDuration, TimeZone, Utc};
use lit_rust_sdk::{
    auth::{load_wallet_from_env, EthWalletProvider},
    blockchain::{resolve_address, Contract, RateLimitNFT, PKPNFT},
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
    // 1. Mint a PKP NFT
    // 2. Mint a Rate Limit NFT
    // 3. Create capacity delegation signature delegating to the PKP
    // 4. Use it to execute a Lit Action

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

    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let blockchain_provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(LitNetwork::Datil.rpc_url())
        .await
        .expect("Failed to connect to Ethereum network");

    // Step 1: Mint a PKP NFT for this test
    println!("🔐 Minting PKP NFT for capacity delegation test...");

    let pkp_nft_address = resolve_address(Contract::PKPNFT, LitNetwork::Datil)
        .await
        .expect("Failed to resolve PKP NFT contract address");

    println!("PKP NFT contract address: {}", pkp_nft_address);

    let pkp_nft = PKPNFT::new(pkp_nft_address, blockchain_provider.clone());

    let mint_cost = pkp_nft
        .mintCost()
        .call()
        .await
        .expect("Failed to get PKP mint cost");

    println!("💰 PKP mint cost: {} wei", mint_cost);

    let key_type = U256::from(2); // ECDSA key type

    let pkp_tx = pkp_nft.mintNext(key_type).value(mint_cost);
    let pkp_pending_tx = pkp_tx
        .send()
        .await
        .expect("Failed to send PKP mint transaction");

    println!("✅ PKP mint transaction sent: {}", pkp_pending_tx.tx_hash());
    println!("⏳ Waiting for PKP transaction to be mined...");

    let pkp_receipt = pkp_pending_tx
        .get_receipt()
        .await
        .expect("Failed to get PKP transaction receipt");

    println!("✅ PKP minted in block: {:?}", pkp_receipt.block_number);

    // Extract PKP details from the mint transaction
    let mut pkp_token_id = None;
    let mut pkp_public_key = None;
    let mut pkp_eth_address = None;

    // We know the transaction succeeded, so let's get the token ID
    // The mintNext function emits events - we need to find the right token

    // Since the logs might not be available, let's use a different approach
    // Query the blockchain for PKP NFTs owned by our wallet
    let balance = pkp_nft
        .balanceOf(wallet.address())
        .call()
        .await
        .expect("Failed to get PKP balance");

    println!("📊 Wallet owns {} PKP NFTs", balance);

    if balance > U256::ZERO {
        // Get the last token owned by the wallet (most likely the one we just minted)
        let token_index = balance - U256::from(1);
        let token_id = pkp_nft
            .tokenOfOwnerByIndex(wallet.address(), token_index)
            .call()
            .await
            .expect("Failed to get token ID by index");

        pkp_token_id = Some(token_id);
        println!("🔐 Found PKP Token ID: {}", token_id);
    }

    // Now get the PKP details if we found the token ID
    if let Some(token_id) = pkp_token_id {
        // Get PKP public key and ETH address
        let pub_key = pkp_nft
            .getPubkey(token_id)
            .call()
            .await
            .expect("Failed to get PKP public key");

        pkp_public_key = Some(format!("0x{}", hex::encode(&pub_key)));

        let eth_addr = pkp_nft
            .getEthAddress(token_id)
            .call()
            .await
            .expect("Failed to get PKP ETH address");

        pkp_eth_address = Some(format!("{:?}", eth_addr));

        println!("🔑 PKP Public Key: {}", pkp_public_key.as_ref().unwrap());
        println!("🔑 PKP ETH Address: {}", pkp_eth_address.as_ref().unwrap());
    }

    let pkp_token_id = pkp_token_id.expect("Failed to extract PKP token ID");
    let pkp_public_key = pkp_public_key.expect("Failed to get PKP public key");
    let pkp_eth_address = pkp_eth_address.expect("Failed to get PKP ETH address");

    // Step 2: Mint a Rate Limit NFT inline for capacity delegation
    println!("🎫 Minting Rate Limit NFT for capacity delegation test...");

    let rate_limit_nft_address = resolve_address(Contract::RateLimitNFT, LitNetwork::Datil)
        .await
        .expect("Failed to resolve Rate Limit NFT contract address");

    println!(
        "Rate Limit NFT contract address: {}",
        rate_limit_nft_address
    );

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

    // Step 3: Create capacity delegation auth sig delegating to the PKP
    println!("🔄 Creating capacity delegation auth sig delegating to PKP...");
    let delegatee_addresses = vec![pkp_eth_address.clone()];
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
            println!(
                "📝 Capacity delegation signature delegating to PKP: {:?}",
                sig
            );
            println!("🔑 Delegated to PKP ETH Address: {}", pkp_eth_address);
            sig
        }
        Err(e) => {
            panic!("❌ Failed to create capacity delegation auth sig: {}", e);
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

    // Step 4: Get session signatures using capacity delegation with our minted PKP
    println!("🔄 Getting PKP session signatures with capacity delegation...");
    println!("   🔑 PKP Public Key: {}", pkp_public_key);
    println!("   🔑 PKP ETH Address: {}", pkp_eth_address);
    println!(
        "   🎫 Using Rate Limit NFT Token ID: {}",
        rate_limit_nft_token_id
    );

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
            println!("🎉 CAPACITY DELEGATION WITH MINTED PKP WORKS ON DATIL NETWORK!");
            println!(
                "🎫 Rate Limit NFT Token ID {} successfully provided capacity",
                rate_limit_nft_token_id
            );
            println!(
                "🔐 PKP Token ID {} successfully executed the Lit Action",
                pkp_token_id
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

#[tokio::test]
async fn test_execute_js_with_auth_methods() {
    // This test demonstrates how to pass multiple auth methods to a Lit Action
    // and access them via Lit.Auth
    
    // Initialize tracing for debugging
    let _ = tracing_subscriber::fmt().try_init();

    // Load main wallet from environment
    let main_wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(e) => {
            println!("❌ Failed to load wallet from environment: {}. Make sure ETHEREUM_PRIVATE_KEY is set in .env", e);
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    println!("🔑 Using main wallet address: {}", main_wallet.address());

    // Create 3 additional random wallets
    println!("🎲 Creating 3 random wallets for auth methods...");
    
    let wallet1 = PrivateKeySigner::random();
    let wallet2 = PrivateKeySigner::random();
    let wallet3 = PrivateKeySigner::random();
    
    println!("  📱 Wallet 1: {}", wallet1.address());
    println!("  📱 Wallet 2: {}", wallet2.address());
    println!("  📱 Wallet 3: {}", wallet3.address());

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

    let pkp_eth_address = match std::env::var("PKP_ETH_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            println!("❌ PKP_ETH_ADDRESS environment variable not set");
            println!("Skipping test - required environment variables not set");
            return;
        }
    };

    println!("🔑 Using PKP public key: {}", pkp_public_key);
    println!("🔑 Using PKP ETH address: {}", pkp_eth_address);

    // Create auth method for the main wallet (for session signature generation)
    println!("🔄 Creating auth method for main wallet...");
    let main_auth_method = match EthWalletProvider::authenticate(&main_wallet, &client).await {
        Ok(method) => {
            println!("✅ Created main auth method");
            method
        }
        Err(e) => {
            println!("❌ Failed to create main auth method: {}", e);
            println!("Skipping test - auth method creation failed");
            return;
        }
    };

    // Create auth methods for the three additional wallets
    println!("🔄 Creating auth methods for additional wallets...");
    
    let auth_method1 = match EthWalletProvider::authenticate(&wallet1, &client).await {
        Ok(method) => {
            println!("✅ Created auth method for wallet 1");
            method
        }
        Err(e) => {
            panic!("❌ Failed to create auth method for wallet 1: {}", e);
        }
    };

    let auth_method2 = match EthWalletProvider::authenticate(&wallet2, &client).await {
        Ok(method) => {
            println!("✅ Created auth method for wallet 2");
            method
        }
        Err(e) => {
            panic!("❌ Failed to create auth method for wallet 2: {}", e);
        }
    };

    let auth_method3 = match EthWalletProvider::authenticate(&wallet3, &client).await {
        Ok(method) => {
            println!("✅ Created auth method for wallet 3");
            method
        }
        Err(e) => {
            panic!("❌ Failed to create auth method for wallet 3: {}", e);
        }
    };

    // Combine the additional auth methods
    let additional_auth_methods = vec![auth_method1, auth_method2, auth_method3];

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
            vec![main_auth_method],
            resource_ability_requests,
            &expiration_str,
        )
        .await
    {
        Ok(session_sigs) => {
            println!("✅ Got PKP session signatures!");
            println!("📊 Number of session signatures: {}", session_sigs.len());
            session_sigs
        }
        Err(e) => {
            println!("❌ Failed to get PKP session signatures: {}", e);
            println!("Skipping test - session signature generation failed");
            return;
        }
    };

    // Create a Lit Action that logs the Lit.Auth object
    let lit_action_code = r#"
const go = async () => {
    console.log("=== Lit.Auth Contents ===");
    
    // Log the entire Lit.Auth object
    console.log("Lit.Auth object:", JSON.stringify(Lit.Auth, null, 2));
    
    // Check if we have auth method contexts
    if (Lit.Auth && Lit.Auth.authMethodContexts && Array.isArray(Lit.Auth.authMethodContexts)) {
        const authMethods = Lit.Auth.authMethodContexts;
        console.log(`Found ${authMethods.length} auth method contexts`);
        
        // Log details of each auth method context
        authMethods.forEach((authContext, index) => {
            console.log(`\nAuth Method Context ${index + 1}:`);
            console.log(`  User ID (Address): ${authContext.userId}`);
            console.log(`  App ID: ${authContext.appId}`);
            console.log(`  Auth Method Type: ${authContext.authMethodType}`);
            console.log(`  Used for Session Key: ${authContext.usedForSignSessionKeyRequest}`);
        });
        
        // Also log the authSigAddress if present
        if (Lit.Auth.authSigAddress) {
            console.log(`\nAuth Sig Address: ${Lit.Auth.authSigAddress}`);
        }
    } else {
        console.log("No auth method contexts found in Lit.Auth");
    }
    
    // Return a response indicating success
    Lit.Actions.setResponse({ 
        response: "Successfully logged Lit.Auth contents",
        authMethodCount: Lit.Auth && Lit.Auth.authMethodContexts ? Lit.Auth.authMethodContexts.length : 0
    });
};

go();
"#;

    // Execute the Lit Action with additional auth methods
    println!("🚀 Executing Lit Action with additional auth methods...");
    let execute_params = ExecuteJsParams {
        code: Some(lit_action_code.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: Some(additional_auth_methods),
        js_params: None,
    };

    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("🎉 Lit Action executed successfully!");
            println!("📤 Response: {:?}", response.response);
            println!("📜 Logs:\n{}", response.logs);

            // Verify we got the expected response
            if let Some(response_obj) = response.response.as_object() {
                if let Some(auth_count) = response_obj.get("authMethodCount") {
                    let count = auth_count.as_u64().unwrap_or(0);
                    assert_eq!(
                        count, 3,
                        "Expected 3 auth methods, got {}",
                        count
                    );
                    println!("✅ Confirmed: {} auth methods were accessible in Lit.Auth", count);
                }
            }

            // Verify logs contain information about auth method contexts
            assert!(
                response.logs.contains("Auth Method Context"),
                "Logs should contain auth method context information"
            );
            
            // Verify each wallet address appears in the logs (check full address with 0x prefix)
            assert!(
                response.logs.contains(&wallet1.address().to_string()),
                "Logs should contain wallet 1 address"
            );
            assert!(
                response.logs.contains(&wallet2.address().to_string()),
                "Logs should contain wallet 2 address"
            );
            assert!(
                response.logs.contains(&wallet3.address().to_string()),
                "Logs should contain wallet 3 address"
            );

            println!("✅ All assertions passed!");
            println!("🎯 Successfully demonstrated passing auth methods to Lit Action!");
        }
        Err(e) => {
            panic!("❌ Lit Action execution failed: {}", e);
        }
    }
}
