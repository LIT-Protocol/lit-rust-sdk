use crate::types::{
    AuthSig, LitResourceAbilityRequest, SessionKeySignedMessage, SessionSignature,
    SessionSignatures,
};
use alloy::signers::local::PrivateKeySigner;
use ed25519_dalek::Signer;
use eyre::Result;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use tracing::info;

impl<P: alloy::providers::Provider> super::LitNodeClient<P> {
    pub async fn get_local_session_sigs(
        &self,
        wallet: &PrivateKeySigner,
        resource_ability_requests: Vec<LitResourceAbilityRequest>,
        expiration: &str,
    ) -> Result<SessionSignatures> {
        if !self.ready {
            return Err(eyre::eyre!("Lit Node Client not connected"));
        }

        // Generate ed25519 keypair for signing
        let session_keypair = {
            let mut secret_bytes = [0u8; 32];
            rand::rngs::OsRng.fill(&mut secret_bytes);
            ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
        };
        let session_verifying_key = session_keypair.verifying_key();
        let session_public_key = hex::encode(session_verifying_key.to_bytes());
        info!("Generated session key: {}", session_public_key);

        // Create auth sig with local wallet
        let auth_sig = self
            .create_auth_sig_for_session_sig(wallet, &session_public_key, &resource_ability_requests)
            .await?;
        info!("Created auth sig for session: {:?}", auth_sig);

        // Generate session signatures for each node
        let mut session_sigs = HashMap::new();
        let now = chrono::Utc::now();
        let issued_at = now.sub(chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let capabilities = vec![auth_sig];

        for node_url in self.connected_nodes() {
            let session_key_signed_message = SessionKeySignedMessage {
                session_key: session_public_key.clone(),
                resource_ability_requests: resource_ability_requests.clone(),
                capabilities: capabilities.clone(),
                issued_at: issued_at.clone(),
                expiration: expiration.to_string(),
                node_address: node_url.to_owned(),
            };
            
            // Serialize to JSON string
            let message = serde_json::to_string(&session_key_signed_message)?;
            
            // Sign message with session key
            let signature = session_keypair.sign(message.as_bytes());
            
            let session_sig = SessionSignature {
                sig: signature.to_string(),
                derived_via: "litSessionSignViaNacl".to_string(),
                signed_message: message,
                address: session_public_key.clone(),
                algo: Some("ed25519".to_string()),
            };
            
            session_sigs.insert(node_url.clone(), session_sig);
        }

        if session_sigs.is_empty() {
            return Err(eyre::eyre!(
                "Failed to create session signatures for any node"
            ));
        }
        
        Ok(session_sigs)
    }

    async fn create_auth_sig_for_session_sig(
        &self,
        wallet: &PrivateKeySigner,
        session_public_key: &str,
        resource_ability_requests: &[LitResourceAbilityRequest],
    ) -> Result<AuthSig> {
        use alloy::signers::Signer;
        use siwe::Message;
        use siwe_recap::Capability;
        
        let wallet_address = wallet.address();
        
        // Create resource capabilities
        let mut resources = vec![];
        let mut resource_prefixes = vec![];
        
        for resource_ability_request in resource_ability_requests.iter() {
            let (resource, resource_prefix) = (
                "*/*".to_string(),
                format!(
                    "{}://*",
                    resource_ability_request.resource.resource_prefix.clone()
                ),
            );
            resources.push(resource);
            resource_prefixes.push(resource_prefix);
        }
        
        let mut capabilities = Capability::<Value>::default();
        for (resource, resource_prefix) in resources.iter().zip(resource_prefixes.iter()) {
            let _ = capabilities
                .with_actions_convert(resource_prefix.clone(), [(resource.clone(), [])]);
        }
        
        // Get latest blockhash for nonce
        let nonce = self.get_latest_ethereum_blockhash().await?;
        
        let now = chrono::Utc::now();
        let siwe_issued_at = now.sub(chrono::Duration::days(1));
        let siwe_expiration_time = now.add(chrono::Duration::days(7));
        
        // Build SIWE message with capabilities
        let siwe_message = capabilities
            .build_message(Message {
                domain: "localhost:3000".parse().unwrap(),
                address: wallet_address.into_array(),
                statement: Some(format!(
                    "I am creating a session for {}.",
                    session_public_key
                )),
                uri: format!("lit:session:{}", session_public_key).parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: nonce,
                issued_at: siwe_issued_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    .parse()
                    .unwrap(),
                expiration_time: Some(
                    siwe_expiration_time
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                        .parse()
                        .unwrap(),
                ),
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .map_err(|e| eyre::eyre!("Could not create SIWE message: {}", e))?;
        
        let message_str = siwe_message.to_string();
        info!("Created SIWE message for auth sig: {}", message_str);
        
        // Sign the SIWE message with the wallet
        let signature = wallet.sign_message(&message_str.as_bytes()).await?;
        let sig_hex = format!("0x{}", hex::encode(signature.as_bytes()));
        
        Ok(AuthSig {
            sig: sig_hex,
            derived_via: "web3.eth.personal.sign".to_string(),
            signed_message: message_str,
            address: wallet_address.to_checksum(None),
            algo: None,
        })
    }

}