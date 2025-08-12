use crate::{
    error::{Error, Result},
    types::{AuthMethod, AuthSig},
    LitNodeClient,
};
use ethers::{
    signers::{LocalWallet, Signer},
    utils::to_checksum,
};
use hex;
use rand;
use serde_json::json;
use siwe::Message;
use std::str::FromStr;
use tracing::info;

pub struct EthWalletProvider;

impl EthWalletProvider {
    pub async fn authenticate(
        wallet: &LocalWallet,
        _lit_node_client: &LitNodeClient,
    ) -> Result<AuthMethod> {
        // Get the wallet address in EIP-55 checksum format
        let address = to_checksum(&wallet.address(), None);

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
        let signature = wallet
            .sign_message(&siwe_message)
            .await
            .map_err(|e| Error::Other(format!("Failed to sign SIWE message: {}", e)))?;

        // Convert signature to hex string
        let sig_hex = format!("0x{}", hex::encode(signature.to_vec()));

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
        wallet: &LocalWallet,
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
        let signature = wallet
            .sign_message(&message_str)
            .await
            .map_err(|e| Error::Other(format!("Failed to sign capacity delegation: {}", e)))?;

        let sig_hex = format!("0x{}", hex::encode(signature.to_vec()));

        Ok(AuthSig {
            sig: sig_hex,
            derived_via: "web3.eth.personal.sign".to_string(),
            signed_message: message_str,
            address: format!("0x{:x}", address),
        })
    }
}

pub fn create_pkp_resource(resource_id: &str) -> crate::types::LitResource {
    crate::types::LitResource {
        resource: format!("lit-pkp://{}", resource_id),
        resource_prefix: "lit-pkp".to_string(),
    }
}

pub fn load_wallet_from_env() -> Result<LocalWallet> {
    dotenv::dotenv().ok(); // Load .env file if it exists

    let private_key = std::env::var("ETHEREUM_PRIVATE_KEY").map_err(|_| {
        Error::Other("ETHEREUM_PRIVATE_KEY environment variable not set".to_string())
    })?;

    // Remove 0x prefix if present
    let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);

    LocalWallet::from_str(private_key)
        .map_err(|e| Error::Other(format!("Invalid private key: {}", e)))
}
