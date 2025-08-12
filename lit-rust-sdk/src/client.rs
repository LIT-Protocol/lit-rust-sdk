use crate::{
    config::{LitNetwork, LitNodeClientConfig},
    error::{Error, Result},
    types::{
        AuthMethod, AuthSig, ConnectionState, HandshakeRequest, HandshakeResponse,
        NodeConnectionInfo, ResourceAbilityRequest, SessionKeySignedMessage, SessionSignature,
        SessionSignatures, SignSessionKeyRequest,
    },
};
use dashmap::DashMap;
use ed25519_dalek::Signer;
use ethers::types::Address;
use rand::{Rng, RngCore};
use reqwest::Client;
use siwe::Message;
use std::{collections::HashMap, sync::Arc};
use tokio::time::timeout;
use tracing::{info, warn};

pub struct LitNodeClient {
    config: LitNodeClientConfig,
    http_client: Client,
    connection_state: Arc<DashMap<String, NodeConnectionInfo>>,
    ready: bool,
    subnet_pub_key: Option<String>,
    network_pub_key: Option<String>,
    network_pub_key_set: Option<String>,
    hd_root_pubkeys: Option<Vec<String>>,
    latest_blockhash: Option<String>,
}

impl LitNodeClient {
    pub fn new(config: LitNodeClientConfig) -> Self {
        let http_client = Client::builder()
            .timeout(config.connect_timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            connection_state: Arc::new(DashMap::new()),
            ready: false,
            subnet_pub_key: None,
            network_pub_key: None,
            network_pub_key_set: None,
            hd_root_pubkeys: None,
            latest_blockhash: None,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!(
            "Starting connection to Lit Network: {:?}",
            self.config.lit_network
        );

        // Get bootstrap URLs
        let bootstrap_urls = self.get_bootstrap_urls().await?;

        if bootstrap_urls.is_empty() {
            return Err(Error::Other("No bootstrap URLs found".to_string()));
        }

        info!("Found {} bootstrap URLs", bootstrap_urls.len());

        // Run handshake with nodes
        let min_node_count = self.config.min_node_count.unwrap_or(2);
        self.handshake_with_nodes(bootstrap_urls, min_node_count)
            .await?;

        // Update network state from consensus
        self.update_network_state_from_consensus();

        self.ready = true;
        info!("Successfully connected to Lit Network");

        Ok(())
    }

    async fn get_bootstrap_urls(&self) -> Result<Vec<String>> {
        match self.config.lit_network {
            LitNetwork::DatilDev => {
                // For dev network, use hardcoded URLs
                Ok(vec![
                    "https://15.235.83.220:7470".to_string(),
                    "https://15.235.83.220:7471".to_string(),
                    "https://15.235.83.220:7472".to_string(),
                ])
            }
            _ => {
                // For other networks, fetch from staking contract
                self.fetch_validator_urls().await
            }
        }
    }

    async fn fetch_validator_urls(&self) -> Result<Vec<String>> {
        let _rpc_url = self
            .config
            .rpc_url
            .as_deref()
            .or_else(|| self.config.lit_network.rpc_url())
            .ok_or_else(|| Error::Other("No RPC URL configured".to_string()))?;

        let _staking_address = self
            .config
            .lit_network
            .staking_contract_address()
            .ok_or_else(|| Error::Other("No staking contract address for network".to_string()))?;

        // For now, return placeholder URLs
        // In a full implementation, we would query the staking contract
        warn!("Validator URL fetching not fully implemented yet");
        Ok(vec![])
    }

    async fn handshake_with_nodes(&mut self, urls: Vec<String>, min_count: usize) -> Result<()> {
        let mut successful_connections = 0;

        for url in urls {
            match self.handshake_with_node(&url).await {
                Ok(response) => {
                    info!("Successfully connected to node: {}", url);
                    self.connection_state.insert(
                        url.clone(),
                        NodeConnectionInfo {
                            url: url.clone(),
                            handshake_response: response,
                        },
                    );
                    successful_connections += 1;
                }
                Err(e) => {
                    warn!("Failed to connect to node {}: {}", url, e);
                }
            }
        }

        if successful_connections < min_count {
            return Err(Error::NotEnoughNodes {
                connected: successful_connections,
                required: min_count,
            });
        }

        Ok(())
    }

    async fn handshake_with_node(&self, url: &str) -> Result<HandshakeResponse> {
        let challenge = self.generate_challenge();
        let request = HandshakeRequest {
            client_public_key: "test".to_string(),
            challenge: challenge.clone(),
        };

        let handshake_url = format!("{}/web/handshake", url);
        let request_id = self.generate_request_id();

        info!("Sending handshake to {}: {:?}", handshake_url, request);

        let response = timeout(
            self.config.connect_timeout,
            self.http_client
                .post(&handshake_url)
                .header("X-Request-Id", request_id)
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
            warn!("Handshake failed with status {}: {}", status, body);
            return Err(Error::HandshakeFailed {
                url: url.to_string(),
                reason: format!("HTTP {} - {}", status, body),
            });
        }

        let body_text = response.text().await.map_err(Error::Network)?;
        info!("Handshake response body: {}", body_text);

        let handshake_response: HandshakeResponse =
            serde_json::from_str(&body_text).map_err(|e| {
                warn!("Failed to parse handshake response: {}", e);
                Error::Serialization(e)
            })?;

        Ok(handshake_response)
    }

    fn generate_challenge(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        hex::encode(bytes)
    }

    fn generate_request_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        hex::encode(bytes)
    }

    fn update_network_state_from_consensus(&mut self) {
        // Collect all handshake responses
        let responses: Vec<HandshakeResponse> = self
            .connection_state
            .iter()
            .map(|entry| entry.handshake_response.clone())
            .collect();

        if responses.is_empty() {
            return;
        }

        // For now, just use the first response
        // In a full implementation, we would find consensus
        let first = &responses[0];

        self.subnet_pub_key = Some(first.subnet_pub_key.clone());
        self.network_pub_key = Some(first.network_pub_key.clone());
        self.network_pub_key_set = Some(first.network_pub_key_set.clone());
        self.hd_root_pubkeys = Some(first.hd_root_pubkeys.clone());
        self.latest_blockhash = Some(first.latest_blockhash.clone());
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn connected_nodes(&self) -> Vec<String> {
        self.connection_state
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_connection_state(&self) -> ConnectionState {
        let mut server_keys = HashMap::new();
        let connected_nodes: Vec<String> = self
            .connection_state
            .iter()
            .map(|entry| {
                server_keys.insert(entry.key().clone(), entry.handshake_response.clone());
                entry.key().clone()
            })
            .collect();

        ConnectionState {
            connected_nodes,
            server_keys,
            subnet_pub_key: self.subnet_pub_key.clone(),
            network_pub_key: self.network_pub_key.clone(),
            network_pub_key_set: self.network_pub_key_set.clone(),
            hd_root_pubkeys: self.hd_root_pubkeys.clone(),
            latest_blockhash: self.latest_blockhash.clone(),
        }
    }

    pub async fn get_pkp_session_sigs(
        &self,
        pkp_public_key: &str,
        pkp_eth_address: &str,
        capability_auth_sigs: Vec<AuthSig>,
        auth_methods: Vec<AuthMethod>,
        resource_ability_requests: Vec<ResourceAbilityRequest>,
        expiration: &str,
    ) -> Result<SessionSignatures> {
        if !self.ready {
            return Err(Error::Other("Client not connected".to_string()));
        }

        // Generate ed25519 keypair for session signatures
        let session_keypair = {
            let mut secret_bytes = [0u8; 32];
            rand::rngs::OsRng.fill(&mut secret_bytes);
            ed25519_dalek::SigningKey::from_bytes(&secret_bytes)
        };
        let session_verifying_key = session_keypair.verifying_key();
        let session_public_key = hex::encode(session_verifying_key.to_bytes());
        let session_key_uri = format!("lit:session:{}", session_public_key);

        info!("Generated session key: {}", session_key_uri);

        // Create SIWE message with resource ability requests
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

        // First, get the delegation signature from the PKP
        let delegation_auth_sig = self
            .get_delegation_signature_from_pkp(
                pkp_public_key,
                pkp_eth_address,
                &auth_methods,
                &siwe_message,
                &session_key_uri,
            )
            .await?;

        // Now create session signatures for each node
        let mut session_sigs = HashMap::new();
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        // Combine all capabilities
        let mut capabilities = vec![delegation_auth_sig];
        capabilities.extend(capability_auth_sigs);

        for node_url in self.connected_nodes() {
            // Create the session key signed message for this node
            let session_key_signed_message = SessionKeySignedMessage {
                session_key: session_public_key.clone(),
                resource_ability_requests: resource_ability_requests.clone(),
                capabilities: capabilities.clone(),
                issued_at: issued_at.clone(),
                expiration: expiration.to_string(),
                node_address: node_url.clone(),
            };

            // Serialize to JSON
            let message =
                serde_json::to_string(&session_key_signed_message).map_err(Error::Serialization)?;

            // Sign with session key
            let signature = session_keypair.sign(message.as_bytes());

            // Create session signature
            let session_sig = SessionSignature {
                sig: signature.to_string(),
                derived_via: "lit-session-sig".to_string(),
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
        resource_ability_requests: &[ResourceAbilityRequest],
        _capability_auth_sigs: &[AuthSig],
        expiration: &str,
        pkp_eth_address: &str,
        session_key_uri: &str,
    ) -> Result<String> {
        // Use PKP ETH address instead of capacity auth sig address
        let address = self.to_checksum_address(pkp_eth_address)?;
        info!("Using PKP ETH address for SIWE message: {}", address);

        // Fetch the latest Ethereum block hash to use as nonce
        let nonce = self.get_latest_ethereum_blockhash().await?;

        // Create a simple ReCap URI for the resources
        // For now, create a basic ReCap structure manually based on Lit Protocol's expected format
        let mut att_map = serde_json::Map::new();

        // For PKP signing resources, add the capabilities
        for req in resource_ability_requests {
            if req.resource.resource_prefix == "lit-pkp" {
                let ability_obj = serde_json::json!({
                    req.ability.clone(): [{}]
                });
                att_map.insert(req.resource.resource.clone(), ability_obj);
            }
        }

        let recap_data = serde_json::json!({
            "att": att_map,
            "prf": []
        });

        // Encode as base64 for the ReCap URI
        let recap_json = recap_data.to_string();
        let recap_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, recap_json);
        let recap_uri = format!("urn:recap:{}", recap_b64);

        // Create the SIWE message with proper format matching the reference implementation
        let statement = "I am delegating to a session key";
        let resources_str = if !resource_ability_requests.is_empty() {
            format!("\nResources:\n- {}", recap_uri)
        } else {
            String::new()
        };

        let message = format!(
            "{} wants you to sign in with your Ethereum account:\n{}\n\n{}{}\n\nURI: {}\nVersion: 1\nChain ID: 1\nNonce: {}\nIssued At: {}\nExpiration Time: {}",
            "localhost:3000",
            address,
            statement,
            resources_str,
            session_key_uri,
            nonce,
            chrono::Utc::now().to_rfc3339(),
            expiration
        );

        info!("Message: {:?}", message);
        // Just for debugging - don't unwrap here as the message might not parse correctly
        if let Ok(parsed_message) = message.parse::<Message>() {
            info!(
                "Parsed message when creating session sig SIWE: {:?}",
                parsed_message
            );
        } else {
            info!("Warning: SIWE message did not parse correctly for logging");
        }

        Ok(message)
    }

    fn to_checksum_address(&self, address: &str) -> Result<String> {
        use ethers::utils::to_checksum;

        // Parse address and convert to checksum format
        let addr: Address = address
            .parse()
            .map_err(|_| Error::Other("Invalid address format".to_string()))?;

        // Use ethers to_checksum function for proper EIP-55 format
        Ok(to_checksum(&addr, None))
    }

    pub async fn create_capacity_delegation_auth_sig(
        &self,
        wallet: &ethers::signers::LocalWallet,
        capacity_token_id: &str,
        delegatee_addresses: &[String],
        uses: &str,
    ) -> Result<AuthSig> {
        crate::auth::EthWalletProvider::create_capacity_delegation_auth_sig(
            wallet,
            capacity_token_id,
            delegatee_addresses,
            uses,
        )
        .await
    }

    async fn get_latest_ethereum_blockhash(&self) -> Result<String> {
        // Load Ethereum RPC URL from environment
        let rpc_url = std::env::var("ETHEREUM_RPC_URL").map_err(|_| {
            Error::Other("ETHEREUM_RPC_URL environment variable not set".to_string())
        })?;

        // Create a simple JSON-RPC request to get the latest block
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
        // Get signatures from all nodes (we need threshold signatures)
        let mut node_responses = Vec::new();

        // same request id for all nodes
        let request_id = self.generate_request_id();

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
                    .header("X-Request-Id", request_id)
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
            let response_json: serde_json::Value =
                serde_json::from_str(&response_body).map_err(Error::Serialization)?;

            node_responses.push(response_json);
        }

        if node_responses.is_empty() {
            return Err(Error::Other(
                "Failed to get delegation signature from any node".to_string(),
            ));
        }

        // For now, we'll use the first response's signature and SIWE message
        // In a real implementation, we'd need to combine BLS signature shares
        let first_response = &node_responses[0];
        let signature = first_response
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Other("No signature in response".to_string()))?
            .to_string();

        Ok(AuthSig {
            sig: signature,
            derived_via: "lit.bls".to_string(),
            signed_message: siwe_message.to_string(),
            address: self.to_checksum_address(pkp_eth_address)?,
        })
    }
}
