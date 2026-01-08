use ethers::signers::{LocalWallet, Signer};
use ethers::utils::to_checksum;
use lit_rust_sdk::{
    create_lit_client, create_siwe_message_with_resources, generate_session_key_pair, naga_dev,
    sign_siwe_with_eoa, AuthConfig, AuthContext, LitAbility, ResourceAbilityRequest,
};
use std::env;

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
            println!("Set LIT_EOA_PRIVATE_KEY or ETHEREUM_PRIVATE_KEY in .env");
            return;
        }
    };

    let wallet: LocalWallet = eoa_private_key
        .parse()
        .expect("Failed to parse private key");
    let wallet_address = to_checksum(&wallet.address(), None);
    println!("🔑 Using wallet address: {}", wallet_address);

    // Connect to Naga Dev network
    let config = naga_dev().with_rpc_url(rpc_url);
    let client = create_lit_client(config)
        .await
        .expect("Failed to connect to Lit Network");

    println!("✅ Connected to Lit Network");

    // Create session key pair and auth context
    let session_key_pair = generate_session_key_pair();
    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        statement: "Lit Protocol Rust SDK - local session sigs test".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::LitActionExecution,
            resource_id: "*".into(),
            data: None,
        }],
    };

    let nonce = client
        .handshake_result()
        .core_node_config
        .latest_blockhash
        .clone();
    let siwe_message = create_siwe_message_with_resources(
        &wallet_address,
        &session_key_pair.public_key,
        &auth_config,
        &nonce,
    )
    .expect("Failed to create SIWE message");

    let auth_sig = sign_siwe_with_eoa(&eoa_private_key, &siwe_message)
        .await
        .expect("Failed to sign SIWE message");

    let auth_context = AuthContext {
        session_key_pair,
        auth_config,
        delegation_auth_sig: auth_sig,
    };

    println!("🔐 Created auth context for Lit Action execution...");

    // Execute the Lit Action with local session signatures
    println!("🚀 Executing Lit Action with local session signatures...");

    let response = client
        .execute_js(
            Some(HELLO_WORLD_LIT_ACTION.to_string()),
            None,
            None,
            &auth_context,
        )
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
            println!("Set LIT_EOA_PRIVATE_KEY or ETHEREUM_PRIVATE_KEY in .env");
            return;
        }
    };

    let wallet: LocalWallet = eoa_private_key
        .parse()
        .expect("Failed to parse private key");
    let wallet_address = to_checksum(&wallet.address(), None);
    println!("🔑 Using wallet address: {}", wallet_address);

    // Connect to Naga Dev network
    let config = naga_dev().with_rpc_url(rpc_url);
    let client = create_lit_client(config)
        .await
        .expect("Failed to connect to Lit Network");

    println!("✅ Connected to Lit Network");

    // Create session key pair and auth context
    let session_key_pair = generate_session_key_pair();
    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        statement: "Lit Protocol Rust SDK - local session sigs test".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::LitActionExecution,
            resource_id: "*".into(),
            data: None,
        }],
    };

    let nonce = client
        .handshake_result()
        .core_node_config
        .latest_blockhash
        .clone();
    let siwe_message = create_siwe_message_with_resources(
        &wallet_address,
        &session_key_pair.public_key,
        &auth_config,
        &nonce,
    )
    .expect("Failed to create SIWE message");

    let auth_sig = sign_siwe_with_eoa(&eoa_private_key, &siwe_message)
        .await
        .expect("Failed to sign SIWE message");

    let auth_context = AuthContext {
        session_key_pair,
        auth_config,
        delegation_auth_sig: auth_sig,
    };

    println!("🔐 Created auth context for Lit Action execution...");

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

    let response = client
        .execute_js(
            Some(lit_action_with_params.to_string()),
            None,
            None,
            &auth_context,
        )
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
