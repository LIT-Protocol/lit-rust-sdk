use lit_rust_sdk::{
    create_eth_wallet_auth_data, create_lit_client, naga_dev, AuthConfig, LitAbility,
    ResourceAbilityRequest,
};

mod common;

use common::{get_eoa_private_key, get_or_mint_pkp, get_rpc_url};

#[tokio::test]
async fn test_pkp_sign_ethereum() {
    let _ = dotenvy::dotenv();

    let rpc_url = match get_rpc_url() {
        Some(url) => url,
        None => {
            println!("Skipping test - no RPC URL configured");
            println!("Set LIT_RPC_URL in .env");
            return;
        }
    };

    let eoa_private_key = match get_eoa_private_key() {
        Some(key) => key,
        None => {
            println!("Skipping test - no EOA private key configured");
            println!("Set LIT_EOA_PRIVATE_KEY in .env");
            return;
        }
    };

    // Get existing PKP or mint a new one
    let pkp_public_key = get_or_mint_pkp(&rpc_url, &eoa_private_key).await;
    println!("Using PKP public key: {}", pkp_public_key);

    // Connect to Naga Dev network
    let config = naga_dev().with_rpc_url(rpc_url);
    let client = create_lit_client(config)
        .await
        .expect("Failed to connect to Lit Network");

    println!("Connected to Lit Network");

    // Create PKP auth context
    let nonce = client
        .handshake_result()
        .core_node_config
        .latest_blockhash
        .clone();

    let auth_data = create_eth_wallet_auth_data(&eoa_private_key, &nonce)
        .await
        .expect("Failed to create auth data");

    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339(),
        statement: "Lit Protocol Rust SDK - PKP signing test".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::PKPSigning,
            resource_id: "*".into(),
            data: None,
        }],
    };

    println!("Creating PKP auth context...");
    let auth_context = client
        .create_pkp_auth_context(&pkp_public_key, auth_data, auth_config, None, None, None)
        .await
        .expect("Failed to create PKP auth context");

    println!("Created PKP auth context successfully");

    // Sign a message
    let message = b"Hello from Rust SDK PKP signing test!";
    println!("Signing message: {}", String::from_utf8_lossy(message));

    let signature = client
        .pkp_sign_ethereum(&pkp_public_key, message, &auth_context, None)
        .await
        .expect("Failed to sign message");

    println!(
        "Signature: {}",
        serde_json::to_string_pretty(&signature).unwrap()
    );

    // Verify signature structure - the combined signature has these fields
    assert!(
        signature.get("signature").is_some(),
        "Signature should have 'signature' field"
    );
    assert!(
        signature.get("verifying_key").is_some(),
        "Signature should have 'verifying_key' field"
    );
    assert!(
        signature.get("signed_data").is_some(),
        "Signature should have 'signed_data' field"
    );
    assert!(
        signature.get("recovery_id").is_some(),
        "Signature should have 'recovery_id' field"
    );

    println!("PKP signing test passed!");
}

#[tokio::test]
async fn test_pkp_auth_context_creation() {
    let _ = dotenvy::dotenv();

    let rpc_url = match get_rpc_url() {
        Some(url) => url,
        None => {
            println!("Skipping test - no RPC URL configured");
            return;
        }
    };

    let eoa_private_key = match get_eoa_private_key() {
        Some(key) => key,
        None => {
            println!("Skipping test - no EOA private key configured");
            return;
        }
    };

    // Get existing PKP or mint a new one
    let pkp_public_key = get_or_mint_pkp(&rpc_url, &eoa_private_key).await;

    // Connect to Naga Dev network
    let config = naga_dev().with_rpc_url(rpc_url);
    let client = create_lit_client(config)
        .await
        .expect("Failed to connect to Lit Network");

    // Create PKP auth context
    let nonce = client
        .handshake_result()
        .core_node_config
        .latest_blockhash
        .clone();

    let auth_data = create_eth_wallet_auth_data(&eoa_private_key, &nonce)
        .await
        .expect("Failed to create auth data");

    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        statement: "Test auth context creation".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::PKPSigning,
            resource_id: "*".into(),
            data: None,
        }],
    };

    // Test auth context creation
    let auth_context = client
        .create_pkp_auth_context(&pkp_public_key, auth_data, auth_config, None, None, None)
        .await
        .expect("Failed to create PKP auth context");

    // Verify auth context components
    assert!(
        !auth_context.session_key_pair.public_key.is_empty(),
        "Session key pair should have public key"
    );
    assert!(
        !auth_context.delegation_auth_sig.sig.is_empty(),
        "Should have delegation auth signature"
    );

    println!("PKP auth context creation test passed!");
}
