use crate::{
    error::{Error, Result},
    types::{AuthMethod, AuthSig},
    LitNodeClient,
};
use ethers::{
    signers::{LocalWallet, Signer},
};
use hex;
use serde_json::json;
use std::str::FromStr;

pub struct EthWalletProvider;

impl EthWalletProvider {
    pub async fn authenticate(
        wallet: &LocalWallet,
        _lit_node_client: &LitNodeClient,
    ) -> Result<AuthMethod> {
        // Get the wallet address
        let address = wallet.address();
        
        // Create the message to sign (similar to JS implementation)
        let message = format!(
            "I am creating an account to use Lit Protocol at {}",
            chrono::Utc::now().timestamp()
        );
        
        // Sign the message
        let signature = wallet.sign_message(&message).await
            .map_err(|e| Error::Other(format!("Failed to sign message: {}", e)))?;
        
        // Convert signature to hex string
        let sig_hex = format!("0x{}", hex::encode(signature.to_vec()));
        
        // Create the auth method
        let auth_method = AuthMethod {
            auth_method_type: 1, // EthWallet auth method type
            access_token: json!({
                "signature": sig_hex,
                "message": message,
                "address": format!("0x{:x}", address)
            }).to_string(),
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
        let signature = wallet.sign_message(&message_str).await
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
    
    let private_key = std::env::var("ETHEREUM_PRIVATE_KEY")
        .map_err(|_| Error::Other("ETHEREUM_PRIVATE_KEY environment variable not set".to_string()))?;
    
    // Remove 0x prefix if present
    let private_key = private_key.strip_prefix("0x").unwrap_or(&private_key);
    
    LocalWallet::from_str(private_key)
        .map_err(|e| Error::Other(format!("Invalid private key: {}", e)))
}