use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use lit_rust_sdk::{
    create_eth_wallet_auth_data, create_lit_client, naga_dev, AuthConfig, LitAbility,
    PkpMintManager, ResourceAbilityRequest,
};
use std::env;
use std::sync::{Arc, OnceLock};

// Cache for minted PKP to avoid minting multiple times during test runs
static MINTED_PKP: OnceLock<String> = OnceLock::new();

fn get_rpc_url() -> Option<String> {
    env::var("LIT_RPC_URL")
        .or_else(|_| env::var("LIT_TXSENDER_RPC_URL"))
        .or_else(|_| env::var("LIT_YELLOWSTONE_PRIVATE_RPC_URL"))
        .or_else(|_| env::var("LOCAL_RPC_URL"))
        .ok()
}

fn normalize_0x_hex(s: String) -> String {
    if s.starts_with("0x") {
        s
    } else {
        format!("0x{s}")
    }
}

fn get_eoa_private_key() -> Option<String> {
    env::var("LIT_EOA_PRIVATE_KEY")
        .or_else(|_| env::var("ETHEREUM_PRIVATE_KEY"))
        .or_else(|_| env::var("LIVE_MASTER_ACCOUNT"))
        .or_else(|_| env::var("LOCAL_MASTER_ACCOUNT"))
        .ok()
        .map(normalize_0x_hex)
}

/// Mint a new PKP if LIT_PKP_PUBLIC_KEY is not set
async fn get_or_mint_pkp(rpc_url: &str, eoa_private_key: &str) -> String {
    // Check if PKP is already set in environment
    if let Ok(pkp) = env::var("LIT_PKP_PUBLIC_KEY").or_else(|_| env::var("PKP_PUBLIC_KEY")) {
        println!("Using existing PKP from environment: {}...", &pkp[..20]);
        return pkp;
    }

    // Check if we already minted a PKP in this test run
    if let Some(pkp) = MINTED_PKP.get() {
        println!("Using cached minted PKP: {}...", &pkp[..20]);
        return pkp.clone();
    }

    // Otherwise, mint a new PKP
    println!("No PKP in environment or cache, minting a new one...");

    let wallet: LocalWallet = eoa_private_key
        .parse()
        .expect("Failed to parse private key");

    let provider = Provider::<Http>::try_from(rpc_url).expect("Failed to create provider");
    let chain_id = provider
        .get_chainid()
        .await
        .expect("Failed to get chain ID")
        .as_u64();
    let signer_wallet = wallet.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, signer_wallet));

    let config = naga_dev().with_rpc_url(rpc_url.to_string());
    let mint_manager =
        PkpMintManager::new(&config, client).expect("Failed to create PkpMintManager");

    let key_type = U256::from(2); // ECDSA
    let key_set_id = "naga-keyset1";

    let mint_result = mint_manager
        .mint_next(key_type, key_set_id)
        .await
        .expect("Failed to mint PKP");

    let pkp = mint_result.data.pubkey.clone();
    println!("Minted new PKP: {}", pkp);

    // Cache the PKP for other tests
    let _ = MINTED_PKP.set(pkp.clone());

    pkp
}

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
