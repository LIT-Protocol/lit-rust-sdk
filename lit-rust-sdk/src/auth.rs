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
        let nonce = format!("0x{}", hex::encode(&rand::random::<[u8; 32]>()));

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
        let signature = wallet.sign_message(&siwe_message.as_bytes()).await?;

        // Convert signature to hex string
        let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));

        // Create the auth method with proper Lit Protocol auth sig format
        let auth_sig = json!({
            "sig": sig_hex,
            "derivedVia": "web3.eth.personal.sign",
            "signedMessage": siwe_message,
            "address": address
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
        let address = wallet.address();

        // Create the capacity delegation message
        let message = json!({
            "capacityTokenId": capacity_token_id,
            "delegateeAddresses": delegatee_addresses,
            "uses": uses,
            "expiration": chrono::Utc::now().timestamp() + 3600, // 1 hour from now
        });

        let message_str = message.to_string();

        // Sign the message
        let signature = wallet.sign_message(&message_str.as_bytes()).await?;

        let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));

        Ok(AuthSig {
            sig: sig_hex,
            derived_via: "web3.eth.personal.sign".to_string(),
            signed_message: message_str,
            address: format!("0x{:x}", address),
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
