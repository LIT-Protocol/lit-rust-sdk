use crate::auth::EthWalletProvider;
use crate::error::{Error, Result};
use crate::types::{
    AuthMethod, AuthSig, JsonSignSessionKeyResponseV1, LitResourceAbilityRequest,
    SessionKeySignedMessage, SessionSignature, SessionSignatures, SignSessionKeyRequest,
};
use ed25519_dalek::Signer;
use ethers::types::Address;
use rand::Rng;
use serde_json::Value;
use siwe::Message;
use siwe_recap::Capability;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use tokio::time::timeout;
use tracing::{info, warn};

impl super::LitNodeClient {
    pub async fn get_pkp_session_sigs(
        &self,
        pkp_public_key: &str,
        pkp_eth_address: &str,
        capability_auth_sigs: Vec<AuthSig>,
        auth_methods: Vec<AuthMethod>,
        resource_ability_requests: Vec<LitResourceAbilityRequest>,
        expiration: &str,
    ) -> Result<SessionSignatures> {
        if !self.ready {
            return Err(Error::Other("Client not connected".to_string()));
        }

        let session_keypair = {
            let mut secret_bytes = [0u8; 32];
            rand::rngs::OsRng.fill(&mut secret_bytes);
            ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
        };
        let session_verifying_key = session_keypair.verifying_key();
        let session_public_key = hex::encode(session_verifying_key.to_bytes());
        let session_key_uri = format!("lit:session:{}", session_public_key);
        info!("Generated session key: {}", session_key_uri);

        let siwe_message = self
            .create_siwe_message(
                &resource_ability_requests,
                &capability_auth_sigs,
                expiration,
                pkp_eth_address,
                &session_key_uri,
            )
            .await?;
        info!("Created SIWE message: {}", siwe_message);

        let delegation_auth_sig = self
            .get_delegation_signature_from_pkp(
                pkp_public_key,
                pkp_eth_address,
                &auth_methods,
                &siwe_message,
                &session_key_uri,
            )
            .await?;
        info!("Delegation auth sig: {:?}", delegation_auth_sig);

        let mut session_sigs = HashMap::new();
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let mut capabilities = vec![delegation_auth_sig];
        capabilities.extend(capability_auth_sigs);

        for node_url in self.connected_nodes() {
            let session_key_signed_message = SessionKeySignedMessage {
                session_key: session_public_key.clone(),
                resource_ability_requests: resource_ability_requests.clone(),
                capabilities: capabilities.clone(),
                issued_at: issued_at.clone(),
                expiration: expiration.to_string(),
                node_address: node_url.to_owned(),
            };
            let message =
                serde_json::to_string(&session_key_signed_message).map_err(Error::Serialization)?;
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
            return Err(Error::Other(
                "Failed to create session signatures for any node".to_string(),
            ));
        }
        Ok(session_sigs)
    }

    async fn create_siwe_message(
        &self,
        resource_ability_requests: &[LitResourceAbilityRequest],
        _capability_auth_sigs: &[AuthSig],
        _expiration: &str,
        pkp_eth_address: &str,
        session_key_uri: &str,
    ) -> Result<String> {
        let address = self.to_checksum_address(pkp_eth_address)?;
        info!("Using PKP ETH address for SIWE message: {}", address);

        let nonce = self.get_latest_ethereum_blockhash().await?;

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

        let eth_address: [u8; 20] = hex::decode(&address[2..])
            .map_err(|e| Error::Other(format!("Failed to decode address: {}", e)))?
            .try_into()
            .map_err(|_| Error::Other("Invalid address length".to_string()))?;

        let now = chrono::Utc::now();
        let siwe_issued_at = now.sub(chrono::Duration::days(1));
        let siwe_expiration_time = now.add(chrono::Duration::days(7));

        let siwe_message = capabilities
            .build_message(Message {
                domain: "localhost:3000".parse().unwrap(),
                address: eth_address,
                statement: Some(r#"I am delegating to a session key"#.into()),
                uri: session_key_uri.parse().unwrap(),
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
            .map_err(|e| Error::Other(format!("Could not create SIWE message: {}", e)))?;

        let message_str = siwe_message.to_string();
        info!("Created SIWE message: {}", message_str);
        Ok(message_str)
    }

    fn to_checksum_address(&self, address: &str) -> Result<String> {
        use ethers::utils::to_checksum;
        let addr: Address = address
            .parse()
            .map_err(|_| Error::Other("Invalid address format".to_string()))?;
        Ok(to_checksum(&addr, None))
    }

    pub async fn create_capacity_delegation_auth_sig(
        &self,
        wallet: &ethers::signers::LocalWallet,
        capacity_token_id: &str,
        delegatee_addresses: &[String],
        uses: &str,
    ) -> Result<AuthSig> {
        EthWalletProvider::create_capacity_delegation_auth_sig(
            wallet,
            capacity_token_id,
            delegatee_addresses,
            uses,
        )
        .await
    }

    async fn get_latest_ethereum_blockhash(&self) -> Result<String> {
        let rpc_url = std::env::var("ETHEREUM_RPC_URL").map_err(|_| {
            Error::Other("ETHEREUM_RPC_URL environment variable not set".to_string())
        })?;
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1
        });
        let response = self
            .http_client
            .post(&rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(Error::Network)?;
        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Failed to fetch latest block: HTTP {}",
                response.status()
            )));
        }
        let response_json: serde_json::Value = response.json().await.map_err(Error::Network)?;
        let block_hash = response_json
            .get("result")
            .and_then(|result| result.get("hash"))
            .and_then(|hash| hash.as_str())
            .ok_or_else(|| {
                Error::Other("Failed to extract block hash from response".to_string())
            })?;
        Ok(block_hash.to_string())
    }

    async fn get_delegation_signature_from_pkp(
        &self,
        pkp_public_key: &str,
        pkp_eth_address: &str,
        auth_methods: &[AuthMethod],
        siwe_message: &str,
        session_key_uri: &str,
    ) -> Result<AuthSig> {
        let mut node_responses = Vec::new();
        let request_id = self.generate_request_id();
        info!("auth methods: {:?}", auth_methods);

        for node_url in self.connected_nodes() {
            let endpoint = format!("{}/web/sign_session_key/v1", node_url);
            let request = SignSessionKeyRequest {
                session_key: session_key_uri.to_string(),
                auth_methods: auth_methods.to_vec(),
                pkp_public_key: pkp_public_key.to_string(),
                siwe_message: siwe_message.to_string(),
                curve_type: "BLS".to_string(),
                epoch: None,
            };
            info!("Signing session key with node: {}", endpoint);
            let response = timeout(
                self.config.connect_timeout,
                self.http_client
                    .post(&endpoint)
                    .header("X-Request-Id", request_id.clone())
                    .json(&request)
                    .send(),
            )
            .await
            .map_err(|_| Error::ConnectionTimeout)?
            .map_err(Error::Network)?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unable to read body".to_string());
                warn!(
                    "Session key signing failed with status {}: {}",
                    status, body
                );
                continue;
            }

            let response_body = response.text().await.map_err(Error::Network)?;
            info!("Session key signing response: {}", response_body);
            node_responses.push(response_body);
        }

        if node_responses.is_empty() {
            return Err(Error::Other(
                "Failed to get delegation signature from any node".to_string(),
            ));
        }

        let parsed_responses: Vec<JsonSignSessionKeyResponseV1> = node_responses
            .iter()
            .map(|response| serde_json::from_str(response).unwrap())
            .collect();
        let one_response_with_share = parsed_responses[0].clone();

        let signature = crate::bls::combine(&parsed_responses)?;

        let bls_root_key_bytes = hex::decode(&one_response_with_share.bls_root_pubkey)
            .map_err(|e| Error::Other(format!("Failed to decode root key: {}", e)))?;
        let data_signed = hex::decode(&one_response_with_share.data_signed)
            .map_err(|e| Error::Other(format!("Failed to decode data_signed: {}", e)))?;
        
        crate::bls::verify(&bls_root_key_bytes, &data_signed, &signature)
            .map_err(|e| Error::Other(format!("Failed to verify signature when getting delegation signature from PKP and locally checking against the root key: {}", e)))?;

        let serialized_signature = serde_json::to_string(&signature)
            .map_err(|e| Error::Other(format!("Failed to serialize signature: {}", e)))?;

        Ok(AuthSig {
            sig: serialized_signature,
            derived_via: "lit.bls".to_string(),
            signed_message: one_response_with_share.siwe_message.clone(),
            address: self.to_checksum_address(pkp_eth_address)?,
            algo: Some("LIT_BLS".to_string()),
        })
    }
}
