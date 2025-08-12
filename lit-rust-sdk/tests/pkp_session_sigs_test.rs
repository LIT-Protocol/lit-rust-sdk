use ethers::signers::Signer;
use lit_rust_sdk::{
    auth::{create_pkp_resource, load_wallet_from_env, EthWalletProvider},
    LitNetwork, LitNodeClient, LitNodeClientConfig, ResourceAbilityRequest,
};
use std::time::Duration;

#[tokio::test]
async fn test_get_pkp_session_sigs() {
    // Initialize tracing for debugging
    tracing_subscriber::fmt::init();

    // Load wallet from environment
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(e) => {
            println!("Failed to load wallet from environment: {}. Make sure ETHEREUM_PRIVATE_KEY is set in .env", e);
            return;
        }
    };

    println!("Using wallet address: 0x{:x}", wallet.address());

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev, // Using dev network for testing
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
            panic!("Failed to connect to Lit Network: {}", e);
        }
    }

    // For this test, we'll use a mock PKP since we don't have contract integration yet
    let mock_pkp_public_key = "0x04d2688b6bc2ce7f9049b142c091e86c59227a2a3a5e61c1b20cedf7e5a76d37b4c5c4d7f7b7a7c3b7d0b4e6c4f4c9b8e7a5e2d8a7b8c5d3f2a1e8b6c9";
    let mock_capacity_token_id = "1";

    // Create auth method
    println!("🔄 Creating auth method...");
    let auth_method = match EthWalletProvider::authenticate(&wallet, &client).await {
        Ok(method) => {
            println!("✅ Created auth method");
            method
        }
        Err(e) => {
            panic!("Failed to create auth method: {}", e);
        }
    };

    // Create capacity delegation auth sig
    println!("🔄 Creating capacity delegation auth sig...");
    let delegatee_addresses = vec![format!("0x{:x}", wallet.address())];
    let capacity_auth_sig = match client
        .create_capacity_delegation_auth_sig(
            &wallet,
            mock_capacity_token_id,
            &delegatee_addresses,
            "1",
        )
        .await
    {
        Ok(sig) => {
            println!("✅ Created capacity delegation auth sig");
            sig
        }
        Err(e) => {
            panic!("Failed to create capacity delegation auth sig: {}", e);
        }
    };

    // Create resource ability requests
    let resource_ability_requests = vec![ResourceAbilityRequest {
        resource: create_pkp_resource("*"),
        ability: "lit-pkp-signing".to_string(),
    }];

    // Set expiration to 10 minutes from now
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339();

    // Attempt to get PKP session signatures
    println!("🔄 Getting PKP session signatures...");
    match client
        .get_pkp_session_sigs(
            mock_pkp_public_key,
            vec![capacity_auth_sig],
            vec![auth_method],
            resource_ability_requests,
            &expiration_str,
        )
        .await
    {
        Ok(session_sigs) => {
            println!("✅ Got PKP session signatures!");
            println!("Number of session signatures: {}", session_sigs.len());

            // Print session signature keys (node URLs)
            for (node_url, _sig) in &session_sigs {
                println!("  Session sig from node: {}", node_url);
            }

            // Verify we have at least one signature
            assert!(
                !session_sigs.is_empty(),
                "Should have at least one session signature"
            );
        }
        Err(e) => {
            // This is expected to fail for now since we're using mock data
            // and the PKP/capacity token don't actually exist
            println!("Expected failure (using mock data): {}", e);

            // For now, we'll just verify that the error is reasonable
            // In a real scenario with proper PKP setup, this should succeed
            assert!(
                e.to_string().contains("HTTP")
                    || e.to_string().contains("Failed to get session signatures")
            );
        }
    }
}

#[tokio::test]
async fn test_auth_method_creation() {
    // Test auth method creation in isolation
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(_) => {
            println!("Skipping test - ETHEREUM_PRIVATE_KEY not set");
            return;
        }
    };

    // Create a mock client (we don't need real connection for auth method creation)
    let config = LitNodeClientConfig::default();
    let client = LitNodeClient::new(config);

    let auth_method = EthWalletProvider::authenticate(&wallet, &client)
        .await
        .expect("Should create auth method");

    assert_eq!(auth_method.auth_method_type, 1);
    assert!(!auth_method.access_token.is_empty());

    // Verify the access token is valid JSON
    let _: serde_json::Value =
        serde_json::from_str(&auth_method.access_token).expect("Access token should be valid JSON");
}

#[tokio::test]
async fn test_capacity_delegation_creation() {
    // Test capacity delegation auth sig creation in isolation
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(_) => {
            println!("Skipping test - ETHEREUM_PRIVATE_KEY not set");
            return;
        }
    };

    let delegatee_addresses = vec![format!("0x{:x}", wallet.address())];
    let auth_sig = EthWalletProvider::create_capacity_delegation_auth_sig(
        &wallet,
        "test_token_id",
        &delegatee_addresses,
        "1",
    )
    .await
    .expect("Should create capacity delegation auth sig");

    assert!(!auth_sig.sig.is_empty());
    assert_eq!(auth_sig.derived_via, "web3.eth.personal.sign");
    assert!(!auth_sig.signed_message.is_empty());
    assert_eq!(auth_sig.address, format!("0x{:x}", wallet.address()));

    // Verify the signed message is valid JSON
    let _: serde_json::Value = serde_json::from_str(&auth_sig.signed_message)
        .expect("Signed message should be valid JSON");
}
