use ethers::signers::{LocalWallet, Signer};
use ethers::utils::to_checksum;
use lit_rust_sdk::{
    create_lit_client, create_siwe_message_with_resources, generate_session_key_pair, naga_dev,
    sign_siwe_with_eoa, AuthConfig, AuthContext, DecryptParams, EncryptParams, LitAbility,
    ResourceAbilityRequest,
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

#[tokio::test]
async fn test_client_side_decryption_with_session_sigs() {
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

    // Create unified access control conditions (EVM example)
    // This condition requires the user to have at least 0 wei balance (always passes)
    let unified_accs = serde_json::json!([
        {
            "conditionType": "evmBasic",
            "contractAddress": "",
            "standardContractType": "",
            "chain": "ethereum",
            "method": "eth_getBalance",
            "parameters": [":userAddress", "latest"],
            "returnValueTest": {
                "comparator": ">=",
                "value": "0"
            }
        }
    ]);

    // Create test data to encrypt
    let test_data =
        b"Secret message that requires wallet ownership to decrypt using client-side decryption!";

    println!("🔒 Encrypting data with access control conditions...");

    // Encrypt the data
    let encrypt_response = client
        .encrypt(EncryptParams {
            data_to_encrypt: test_data.to_vec(),
            unified_access_control_conditions: Some(unified_accs.clone()),
            hashed_access_control_conditions_hex: None,
            metadata: None,
        })
        .await
        .expect("Failed to encrypt data");

    println!("✅ Data encrypted successfully!");
    println!(
        "📦 Ciphertext length: {} chars",
        encrypt_response.ciphertext_base64.len()
    );
    println!(
        "🔗 Data hash: {}",
        encrypt_response.data_to_encrypt_hash_hex
    );

    // Now prepare to decrypt by creating session signatures
    let session_key_pair = generate_session_key_pair();
    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        statement: "Lit Protocol Rust SDK - encrypt/decrypt test".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::AccessControlConditionDecryption,
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

    println!("🔄 Created session signatures for decryption...");

    // Now decrypt using client-side decryption
    println!("🔓 Decrypting data using client-side decryption...");

    let decrypt_response = client
        .decrypt(
            DecryptParams {
                ciphertext_base64: encrypt_response.ciphertext_base64,
                data_to_encrypt_hash_hex: encrypt_response.data_to_encrypt_hash_hex,
                unified_access_control_conditions: Some(unified_accs),
                hashed_access_control_conditions_hex: None,
            },
            &auth_context,
            "ethereum",
        )
        .await
        .expect("Failed to decrypt data");

    // Verify the decrypted data matches the original
    let decrypted_str = String::from_utf8_lossy(&decrypt_response.decrypted_data);
    let original_str = String::from_utf8_lossy(test_data);

    println!("🔓 Decrypted content: {}", decrypted_str);

    assert_eq!(
        decrypted_str, original_str,
        "Decrypted data should match original data"
    );

    println!("✅ Decryption successful - data matches original!");
    println!("✅ Full encrypt/decrypt test with client-side decryption completed successfully!");
}

#[tokio::test]
async fn test_client_side_decryption_with_session_sigs_and_evm_contract_conditions() {
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

    let usdc_address_on_eth = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    // Create EVM contract condition that hits the USDC contract and checks for balance >=0
    // This uses the unified access control conditions format
    let unified_accs = serde_json::json!([
        {
            "conditionType": "evmContract",
            "contractAddress": usdc_address_on_eth,
            "functionName": "balanceOf",
            "functionParams": [":userAddress"],
            "functionAbi": {
                "name": "balanceOf",
                "inputs": [
                    {
                        "internalType": "address",
                        "name": "account",
                        "type": "address"
                    }
                ],
                "outputs": [
                    {
                        "internalType": "uint256",
                        "name": "",
                        "type": "uint256"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            "chain": "ethereum",
            "returnValueTest": {
                "key": "",
                "comparator": ">=",
                "value": "0"
            }
        }
    ]);

    // Create test data to encrypt
    let test_data =
        b"Secret message that requires wallet ownership to decrypt using client-side decryption!";

    println!("🔒 Encrypting data with EVM contract conditions...");

    // Encrypt the data
    let encrypt_response = client
        .encrypt(EncryptParams {
            data_to_encrypt: test_data.to_vec(),
            unified_access_control_conditions: Some(unified_accs.clone()),
            hashed_access_control_conditions_hex: None,
            metadata: None,
        })
        .await
        .expect("Failed to encrypt data");

    println!("✅ Data encrypted successfully!");
    println!(
        "📦 Ciphertext length: {} chars",
        encrypt_response.ciphertext_base64.len()
    );
    println!(
        "🔗 Data hash: {}",
        encrypt_response.data_to_encrypt_hash_hex
    );

    // Now prepare to decrypt by creating session signatures
    let session_key_pair = generate_session_key_pair();
    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        statement: "Lit Protocol Rust SDK - encrypt/decrypt test".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::AccessControlConditionDecryption,
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

    println!("🔄 Created session signatures for decryption...");

    // Now decrypt using client-side decryption
    println!("🔓 Decrypting data using client-side decryption...");

    let decrypt_response = client
        .decrypt(
            DecryptParams {
                ciphertext_base64: encrypt_response.ciphertext_base64,
                data_to_encrypt_hash_hex: encrypt_response.data_to_encrypt_hash_hex,
                unified_access_control_conditions: Some(unified_accs),
                hashed_access_control_conditions_hex: None,
            },
            &auth_context,
            "ethereum",
        )
        .await
        .expect("Failed to decrypt data");

    // Verify the decrypted data matches the original
    let decrypted_str = String::from_utf8_lossy(&decrypt_response.decrypted_data);
    let original_str = String::from_utf8_lossy(test_data);

    println!("🔓 Decrypted content: {}", decrypted_str);

    assert_eq!(
        decrypted_str, original_str,
        "Decrypted data should match original data"
    );

    println!("✅ Decryption successful - data matches original!");
    println!("✅ Full encrypt/decrypt test with client-side decryption completed successfully!");
}
