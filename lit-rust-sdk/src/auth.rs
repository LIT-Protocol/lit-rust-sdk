use crate::{
    types::{AuthMethod, AuthSig},
    LitNodeClient,
};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use eyre::Result;
use hex;
use rand;
use serde_json::json;
use siwe::Message;
use tracing::info;

pub struct EthWalletProvider;

impl EthWalletProvider {
    pub async fn authenticate(
        wallet: &PrivateKeySigner,
        _lit_node_client: &LitNodeClient,
    ) -> Result<AuthMethod> {
        // Get the wallet address in EIP-55 checksum format
        let address = wallet.address();

        // Create nonce
        let nonce = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));

        // Create SIWE message for authentication
        let issued_at = chrono::Utc::now().to_rfc3339();
        let expiration = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

        let siwe_message = format!(
            "localhost wants you to sign in with your Ethereum account:\n{}\n\n\nURI: http://localhost\nVersion: 1\nChain ID: 1\nNonce: {}\nIssued At: {}\nExpiration Time: {}",
            address,
            nonce,
            issued_at,
            expiration
        );

        // ensure the message will be parsed correctly
        let parsed_message: Message = siwe_message.parse().unwrap();
        info!("Parsed message: {:?}", parsed_message);

        // Sign the SIWE message
        let signature = wallet.sign_message(siwe_message.as_bytes()).await?;

        // Convert signature to hex string
        let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));

        // Create the auth method with proper Lit Protocol auth sig format
        let auth_sig = json!({
            "sig": sig_hex,
            "derivedVia": "web3.eth.personal.sign",
            "signedMessage": siwe_message,
            "address": address.to_checksum(None)
        });

        let auth_method = AuthMethod {
            auth_method_type: 1, // EthWallet auth method type
            access_token: auth_sig.to_string(),
        };

        Ok(auth_method)
    }

    pub async fn create_capacity_delegation_auth_sig(
        wallet: &PrivateKeySigner,
        capacity_token_id: &str,
        delegatee_addresses: &[String],
        uses: &str,
    ) -> Result<AuthSig> {
        use serde_json::Value;
        use siwe_recap::Capability;
        use std::collections::BTreeMap;

        let address = wallet.address();

        // Create the nota bene data for the capability
        let mut notabene = BTreeMap::new();
        notabene.insert(
            "nft_id".to_string(),
            Value::from(vec![Value::from(capacity_token_id)]),
        );
        notabene.insert("uses".to_string(), Value::from(uses.to_string()));
        notabene.insert(
            "delegate_to".to_string(),
            Value::from(
                delegatee_addresses
                    .iter()
                    .map(|addr| {
                        // Remove 0x prefix if present for the delegate_to field
                        Value::from(if let Some(stripped) = addr.strip_prefix("0x") {
                            stripped.to_string()
                        } else {
                            addr.to_string()
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
        );

        // Create nonce - use a random hex string
        let nonce = hex::encode(rand::random::<[u8; 16]>());

        // Create SIWE message for capacity delegation
        let issued_at = chrono::Utc::now();
        let expiration = issued_at + chrono::Duration::hours(24);

        // Build the capability
        let mut capabilities = Capability::<Value>::default();
        let resource = "Auth/Auth".to_string();
        let resource_prefix = format!("lit-ratelimitincrease://{}", capacity_token_id);

        let capabilities = capabilities
            .with_actions_convert(resource_prefix, [(resource, [notabene])])
            .map_err(|e| eyre::eyre!("Failed to create capability: {}", e))?;

        // Build the SIWE message with the capability
        let siwe_message = capabilities
            .build_message(Message {
                domain: "lit-protocol.com".parse().unwrap(),
                address: address.0.into(),
                statement: Some("Lit Protocol PKP sessionSig".to_string()),
                uri: "lit:capability:delegation".parse().unwrap(),
                version: "1".parse().unwrap(),
                chain_id: 1,
                nonce: nonce.clone(),
                issued_at: issued_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    .parse()
                    .unwrap(),
                expiration_time: Some(
                    expiration
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                        .parse()
                        .unwrap(),
                ),
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .map_err(|e| eyre::eyre!("Failed to build SIWE message: {}", e))?;

        // Prepare the message string
        let message_str = siwe_message.to_string();

        // Sign the SIWE message
        let signature = wallet.sign_message(message_str.as_bytes()).await?;

        let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));

        Ok(AuthSig {
            sig: sig_hex,
            derived_via: "web3.eth.personal.sign".to_string(),
            signed_message: message_str,
            address: address.to_checksum(None),
            algo: None,
        })
    }
}

pub fn load_wallet_from_env() -> Result<PrivateKeySigner> {
    dotenv::dotenv().ok(); // Load .env file if it exists

    let private_key = std::env::var("ETHEREUM_PRIVATE_KEY")
        .map_err(|_| eyre::eyre!("ETHEREUM_PRIVATE_KEY environment variable not set"))?;

    match private_key.parse() {
        Ok(signer) => Ok(signer),
        Err(e) => Err(eyre::eyre!("Invalid private key: {}", e)),
    }
}
