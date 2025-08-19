use lit_rust_sdk::{
    auth::{load_wallet_from_env, EthWalletProvider},
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    LitNetwork, LitNodeClient, LitNodeClientConfig,
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

    println!("Using wallet address: {}", wallet.address());

    // Create client configuration
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev, // Using dev network for testing
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
            panic!("Failed to connect to Lit Network: {}", e);
        }
    }

    // Load real PKP from environment
    let pkp_public_key =
        std::env::var("PKP_PUBLIC_KEY").expect("PKP_PUBLIC_KEY environment variable not set");
    let pkp_token_id =
        std::env::var("PKP_TOKEN_ID").expect("PKP_TOKEN_ID environment variable not set");
    let pkp_eth_address =
        std::env::var("PKP_ETH_ADDRESS").expect("PKP_ETH_ADDRESS environment variable not set");

    println!("Using PKP public key: {}", pkp_public_key);
    println!("Using PKP token ID: {}", pkp_token_id);
    println!("Using PKP ETH address: {}", pkp_eth_address);

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

    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-pkp://".to_string(),
        },
        ability: LitAbility::PKPSigning.to_string(),
    }];

    // Set expiration to 10 minutes from now
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let expiration_str = expiration.to_rfc3339();

    // Attempt to get PKP session signatures
    println!("🔄 Getting PKP session signatures...");
    match client
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
            println!("Number of session signatures: {}", session_sigs.len());

            // Print session signature keys (node URLs)
            for node_url in session_sigs.keys() {
                println!("  Session sig from node: {}", node_url);
            }

            // Verify we have at least one signature
            assert!(
                !session_sigs.is_empty(),
                "Should have at least one session signature"
            );
        }
        Err(e) => {
            // This should now succeed with real PKP data, so panic if it fails
            panic!("Failed to get PKP session signatures: {}", e);
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
    let client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

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

    let delegatee_addresses = vec![wallet.address().to_string()];
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
    assert_eq!(auth_sig.address, wallet.address().to_string());
}
