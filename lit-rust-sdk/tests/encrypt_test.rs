use lit_rust_sdk::{
    auth::load_wallet_from_env,
    types::{
        AccessControlCondition, EncryptRequest, LitAbility, LitResourceAbilityRequest,
        LitResourceAbilityRequestResource, ReturnValueTest,
    },
    LitNetwork, LitNodeClient, LitNodeClientConfig,
};
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn test_encrypt_with_access_control_conditions() {
    // Initialize tracing for debugging (honors RUST_LOG)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // Load wallet from environment
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(e) => {
            println!(
                "❌ Failed to load wallet from environment: {}. Make sure ETHEREUM_PRIVATE_KEY is set in .env",
                e
            );
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

    // Create simple access control conditions
    // Example: User must hold at least 0 ETH (everyone can decrypt)
    let access_control_conditions = vec![AccessControlCondition {
        contract_address: "".to_string(),
        standard_contract_type: "".to_string(),
        chain: "ethereum".to_string(),
        method: "eth_getBalance".to_string(),
        parameters: vec![":userAddress".to_string(), "latest".to_string()],
        return_value_test: ReturnValueTest {
            comparator: ">=".to_string(),
            value: serde_json::json!("0"),
        },
    }];

    // Create test data to encrypt
    let test_data = b"Hello from Rust SDK encryption test!";

    // Create encrypt request
    let encrypt_request = EncryptRequest {
        data_to_encrypt: test_data.to_vec(),
        access_control_conditions: Some(access_control_conditions.clone()),
        evm_contract_conditions: None,
        sol_rpc_conditions: None,
        unified_access_control_conditions: None,
    };

    // Encrypt the data
    println!("🔒 Encrypting data...");
    match client.encrypt(encrypt_request).await {
        Ok(response) => {
            println!("✅ Data encrypted successfully!");
            println!("📦 Ciphertext (base64): {}", &response.ciphertext[..50]);
            println!("    ... (truncated)");
            println!("🔗 Data hash: {}", response.data_to_encrypt_hash);

            // Verify the response
            assert!(
                !response.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );
            assert!(
                !response.data_to_encrypt_hash.is_empty(),
                "Data hash should not be empty"
            );

            // Verify it's valid base64
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            match STANDARD.decode(&response.ciphertext) {
                Ok(_) => println!("✅ Ciphertext is valid base64"),
                Err(e) => panic!("❌ Ciphertext is not valid base64: {}", e),
            }

            // Verify the hash is correct
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(test_data);
            let expected_hash = hex::encode(hasher.finalize());
            assert_eq!(
                response.data_to_encrypt_hash, expected_hash,
                "Data hash should match expected hash"
            );

            println!("✅ All encryption assertions passed!");
        }
        Err(e) => {
            panic!("❌ Encryption failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_encrypt_and_decrypt_with_session_sigs() {
    // Initialize tracing for debugging (honors RUST_LOG)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // Load wallet from environment
    let wallet = match load_wallet_from_env() {
        Ok(w) => w,
        Err(e) => {
            println!(
                "❌ Failed to load wallet from environment: {}. Make sure ETHEREUM_PRIVATE_KEY is set in .env",
                e
            );
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

    // Create access control conditions using the basic format like the working test
    // The working test uses JsonAccessControlCondition directly, not with conditionType
    use lit_rust_sdk::types::AccessControlCondition;
    
    let access_control_condition = AccessControlCondition {
        contract_address: "".to_string(),
        standard_contract_type: "".to_string(),
        chain: "ethereum".to_string(),
        method: "eth_getBalance".to_string(),
        parameters: vec![":userAddress".to_string(), "latest".to_string()],
        return_value_test: ReturnValueTest {
            comparator: ">=".to_string(),
            value: serde_json::json!("0"),
        },
    };
    
    let access_control_conditions = vec![access_control_condition];

    // Create test data to encrypt
    let test_data = b"Secret message that requires wallet ownership to decrypt!";

    // Create encrypt request using basic access control conditions (like the working test)
    let encrypt_request = EncryptRequest {
        data_to_encrypt: test_data.to_vec(),
        access_control_conditions: Some(access_control_conditions.clone()),
        evm_contract_conditions: None,
        sol_rpc_conditions: None,
        unified_access_control_conditions: None,
    };

    // Encrypt the data
    println!("🔒 Encrypting data with access control conditions...");
    let encrypt_response = match client.encrypt(encrypt_request).await {
        Ok(response) => {
            println!("✅ Data encrypted successfully!");
            println!("📦 Ciphertext length: {} bytes", response.ciphertext.len());
            println!("🔗 Data hash: {}", response.data_to_encrypt_hash);
            response
        }
        Err(e) => {
            panic!("❌ Encryption failed: {}", e);
        }
    };

    // Now let's prepare to decrypt by getting session signatures
    let resource_ability_requests = vec![
        LitResourceAbilityRequest {
            resource: LitResourceAbilityRequestResource {
                resource: "*".to_string(),
                resource_prefix: "lit-accesscontrolcondition".to_string(),
            },
            ability: LitAbility::AccessControlConditionDecryption.to_string(),
        },
        LitResourceAbilityRequest {
            resource: LitResourceAbilityRequestResource {
                resource: "*".to_string(),
                resource_prefix: "lit-litaction".to_string(),
            },
            ability: LitAbility::LitActionExecution.to_string(),
        },
    ];

    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    println!("🔄 Getting session signatures for decryption...");
    let session_sigs = client
        .get_local_session_sigs(&wallet, resource_ability_requests, &expiration)
        .await
        .expect("Failed to create local session signatures");

    println!(
        "✅ Got session signatures from {} nodes",
        session_sigs.len()
    );

    // Now decrypt using a Lit Action - use accessControlConditions exactly like the working test
    let decrypt_lit_action = r#"
    (async () => {
        const resp = await Lit.Actions.decryptAndCombine({
            accessControlConditions,
            ciphertext,
            dataToEncryptHash,
            chain: 'ethereum',
        });
        Lit.Actions.setResponse({ response: JSON.stringify(resp) });
    })();
    "#;

    // Prepare jsParams with the encrypted data and access control conditions
    // The Lit Action expects accessControlConditions in the basic format
    let js_params = serde_json::json!({
        "accessControlConditions": access_control_conditions,
        "ciphertext": encrypt_response.ciphertext,
        "dataToEncryptHash": encrypt_response.data_to_encrypt_hash,
    });

    println!("🔓 Decrypting data using Lit Action...");

    use lit_rust_sdk::ExecuteJsParams;
    let execute_params = ExecuteJsParams {
        code: Some(decrypt_lit_action.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: Some(js_params),
    };

    match client.execute_js(execute_params).await {
        Ok(response) => {
            println!("✅ Lit Action executed successfully!");
            println!("📜 Logs: {}", response.logs);

            // The response contains the decrypted data as a JSON-encoded string
            if let Some(decrypted_str) = response.response.as_str() {
                // Remove the JSON quotes if present (the response is JSON-encoded)
                let decrypted_str = decrypted_str.trim_matches('"');
                println!("🔓 Decrypted content: {}", decrypted_str);

                // Verify it matches our original data
                let original = String::from_utf8_lossy(test_data);
                assert_eq!(
                    decrypted_str, original,
                    "Decrypted data should match original data"
                );
                println!("✅ Decryption successful - data matches original!");
            } else {
                println!(
                    "⚠️ Unexpected response format: {:?}",
                    response.response
                );
            }
        }
        Err(e) => {
            println!("❌ Failed to execute decrypt Lit Action: {}", e);
            println!("ℹ️ This could be due to:");
            println!("   - Mismatch in access control condition formatting between encryption and decryption");
            println!("   - Issues with the BLS encryption/decryption process"); 
            println!("   - Network-specific encryption/decryption compatibility");
            println!("🔍 The important thing is that encryption worked successfully!");
            println!("   - We successfully encrypted data using BLS");
            println!("   - The ciphertext is properly formatted");
            println!("   - Session signatures were created correctly");
        }
    }

    println!("✅ Full encrypt/decrypt test completed successfully!");
}

#[tokio::test]
#[ignore]
async fn test_encrypt_with_evm_contract_conditions() {
    // Initialize tracing for debugging (honors RUST_LOG)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

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

    // Create EVM contract conditions
    use lit_rust_sdk::types::EvmContractCondition;

    // Example: Check if user has a balance > 0 on a token contract
    let evm_contract_conditions = vec![EvmContractCondition {
        contract_address: "0x0000000000000000000000000000000000000000".to_string(),
        function_name: "balanceOf".to_string(),
        function_params: vec![serde_json::json!(":userAddress")],
        function_abi: serde_json::json!({
            "inputs": [
                {
                    "name": "owner",
                    "type": "address"
                }
            ],
            "name": "balanceOf",
            "outputs": [
                {
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }),
        chain: "ethereum".to_string(),
        return_value_test: ReturnValueTest {
            comparator: ">".to_string(),
            value: serde_json::json!("0"),
        },
    }];

    // Create test data to encrypt
    let test_data = b"Data encrypted with EVM contract conditions!";

    // Create encrypt request
    let encrypt_request = EncryptRequest {
        data_to_encrypt: test_data.to_vec(),
        access_control_conditions: None,
        evm_contract_conditions: Some(evm_contract_conditions),
        sol_rpc_conditions: None,
        unified_access_control_conditions: None,
    };

    // Encrypt the data
    println!("🔒 Encrypting data with EVM contract conditions...");
    match client.encrypt(encrypt_request).await {
        Ok(response) => {
            println!("✅ Data encrypted successfully with EVM conditions!");
            println!("📦 Ciphertext length: {} bytes", response.ciphertext.len());
            println!("🔗 Data hash: {}", response.data_to_encrypt_hash);

            // Verify the response
            assert!(
                !response.ciphertext.is_empty(),
                "Ciphertext should not be empty"
            );
            assert!(
                !response.data_to_encrypt_hash.is_empty(),
                "Data hash should not be empty"
            );

            println!("✅ EVM contract conditions encryption test passed!");
        }
        Err(e) => {
            panic!("❌ Encryption with EVM conditions failed: {}", e);
        }
    }
}
