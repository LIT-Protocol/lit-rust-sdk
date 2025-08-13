use crate::{
    config::{LitNetwork, LitNodeClientConfig},
    error::{Error, Result},
    types::{
        AuthMethod, AuthSig, ConnectionState, ExecuteJsParams, ExecuteJsResponse, HandshakeRequest,
        HandshakeResponse, NodeConnectionInfo, NodeShare, ResourceAbilityRequest,
        SessionKeySignedMessage, SessionSignature, SessionSignatures, SignSessionKeyRequest,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use blsful::{inner_types::GroupEncoding, Bls12381G2Impl, Signature, SignatureShare};
use dashmap::DashMap;
use ed25519_dalek::Signer;
use ethers::types::Address;
use rand::Rng;
use reqwest::Client;
use serde_json::Value;
use siwe::Message;
use siwe_recap::Capability;
use std::ops::{Add, Sub};
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

            // Convert signature to hex and add a recovery ID byte (65 bytes = 130 hex chars)
            // Ed25519 signatures don't have recovery IDs, so we append 0x00
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(0x00); // Add recovery ID byte
            let sig_hex = hex::encode(sig_bytes);

            // Create session signature
            // For session signatures, use the session public key as address
            // But truncate to 20 bytes (40 hex chars) to match Ethereum address format
            let session_address = if session_public_key.len() > 40 {
                session_public_key[..40].to_string()
            } else {
                session_public_key.clone()
            };

            let session_sig = SessionSignature {
                sig: sig_hex,
                derived_via: "lit-session-sig".to_string(),
                signed_message: message,
                address: session_address,
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
        _expiration: &str,
        pkp_eth_address: &str,
        session_key_uri: &str,
    ) -> Result<String> {
        // Use PKP ETH address instead of capacity auth sig address
        let address = self.to_checksum_address(pkp_eth_address)?;
        info!("Using PKP ETH address for SIWE message: {}", address);

        // Fetch the latest Ethereum block hash to use as nonce
        let nonce = self.get_latest_ethereum_blockhash().await?;

        // Create capabilities using siwe_recap::Capability like the reference implementation
        let mut capabilities = Capability::<Value>::default();

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

        for (resource, resource_prefix) in resources.iter().zip(resource_prefixes.iter()) {
            let _ = capabilities
                .with_actions_convert(resource_prefix.clone(), [(resource.clone(), [])]);
        }

        // Parse the ETH address
        let eth_address: [u8; 20] = hex::decode(&address[2..])
            .map_err(|e| Error::Other(format!("Failed to decode address: {}", e)))?
            .try_into()
            .map_err(|_| Error::Other("Invalid address length".to_string()))?;

        // Generate a SIWE message using the reference implementation format
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
            let response_json: serde_json::Value =
                serde_json::from_str(&response_body).map_err(Error::Serialization)?;

            node_responses.push(response_json);
        }

        if node_responses.is_empty() {
            return Err(Error::Other(
                "Failed to get delegation signature from any node".to_string(),
            ));
        }

        // Extract all signature shares from node_responses, supporting both string and object forms
        let mut signature_shares = Vec::new();
        for response in &node_responses {
            if let Some(signature_share_val) = response.get("signatureShare") {
                match signature_share_val {
                    serde_json::Value::Object(obj) => {
                        // If it's an object, use it directly and include the ProofOfPosession key
                        signature_shares.push(serde_json::to_string(obj).unwrap());
                    }
                    _ => {
                        // Ignore other types
                    }
                }
            }
        }

        let signature_bytes = self.combine_bls_signature_shares(&signature_shares)?;
        let signature = hex::encode(signature_bytes);

        Ok(AuthSig {
            sig: signature,
            derived_via: "lit.bls".to_string(),
            signed_message: siwe_message.to_string(),
            address: self.to_checksum_address(pkp_eth_address)?,
        })
    }

    pub async fn execute_js(&self, params: ExecuteJsParams) -> Result<ExecuteJsResponse> {
        if !self.ready {
            return Err(Error::Other("Client not connected".to_string()));
        }

        if params.code.is_none() && params.ipfs_id.is_none() {
            return Err(Error::Other(
                "Either code or ipfsId must be provided".to_string(),
            ));
        }

        // Generate request ID for this execution
        let request_id = self.generate_request_id();
        info!("Executing Lit Action with request ID: {}", request_id);

        // Get node promises
        let mut node_responses = Vec::new();
        let min_responses = (self.connected_nodes().len() * 2 / 3) + 1; // Require 2/3 + 1 responses

        for node_url in self.connected_nodes() {
            match self
                .execute_js_node_request(&node_url, &params, &request_id)
                .await
            {
                Ok(response) => {
                    info!("Got response from node: {}", node_url);
                    node_responses.push(response);
                }
                Err(e) => {
                    warn!("Failed to get response from node {}: {}", node_url, e);
                }
            }
        }

        if node_responses.len() < min_responses {
            return Err(Error::Other(format!(
                "Not enough successful responses. Got {}, need {}",
                node_responses.len(),
                min_responses
            )));
        }

        // Find the most common response
        let most_common_response = self.find_most_common_response(&node_responses)?;

        // Check if we have any signed data or claim data to aggregate
        let has_signed_data = !most_common_response.signed_data.is_empty();
        let has_claim_data = !most_common_response.claim_data.is_empty();

        // If successful but no signing/claiming, return the response directly
        if most_common_response.success && !has_signed_data && !has_claim_data {
            return Ok(ExecuteJsResponse {
                claims: HashMap::new(),
                signatures: None,
                decryptions: vec![],
                response: most_common_response.response,
                logs: most_common_response.logs,
            });
        }

        // If not successful and no signed/claim data, this is an error case
        if !has_signed_data && !has_claim_data {
            return Ok(ExecuteJsResponse {
                claims: HashMap::new(),
                signatures: None,
                decryptions: vec![],
                response: most_common_response.response,
                logs: most_common_response.logs,
            });
        }

        // Combine BLS signature shares from all nodes
        // let combined_signatures = self.collect_signature_shares(&node_responses)?;

        Ok(ExecuteJsResponse {
            claims: most_common_response.claim_data,
            signatures: None,
            decryptions: vec![],
            response: most_common_response.response,
            logs: most_common_response.logs,
        })
    }

    async fn execute_js_node_request(
        &self,
        node_url: &str,
        params: &ExecuteJsParams,
        request_id: &str,
    ) -> Result<NodeShare> {
        let endpoint = format!("{}/web/execute", node_url);

        // Get the session signature for this specific node URL
        let session_sig = self.get_session_sig_by_url(&params.session_sigs, node_url)?;

        // Prepare the request body based on the JS SDK implementation
        let mut request_body = serde_json::json!({
            "authSig": session_sig,
        });

        if let Some(code) = &params.code {
            // Encode the code as base64, similar to the JS SDK
            let encoded_code = BASE64.encode(code.as_bytes());
            request_body["code"] = serde_json::Value::String(encoded_code);
        }

        if let Some(ipfs_id) = &params.ipfs_id {
            request_body["ipfsId"] = serde_json::Value::String(ipfs_id.clone());
        }

        if let Some(auth_methods) = &params.auth_methods {
            request_body["authMethods"] =
                serde_json::to_value(auth_methods).map_err(Error::Serialization)?;
        }

        if let Some(js_params) = &params.js_params {
            request_body["jsParams"] = js_params.clone();
        }

        info!("Sending execute request to {}: {}", endpoint, request_body);

        let response = timeout(
            self.config.connect_timeout,
            self.http_client
                .post(&endpoint)
                .header("X-Request-Id", request_id)
                .json(&request_body)
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
            warn!("Execute JS failed with status {}: {}", status, body);
            return Err(Error::Other(format!("HTTP {} - {}", status, body)));
        }

        let response_body = response.text().await.map_err(Error::Network)?;
        info!("Execute JS response from {}: {}", node_url, response_body);

        let node_response: NodeShare = serde_json::from_str(&response_body).map_err(|e| {
            warn!("Failed to parse execute JS response: {}", e);
            Error::Serialization(e)
        })?;

        Ok(node_response)
    }

    fn find_most_common_response(&self, responses: &[NodeShare]) -> Result<NodeShare> {
        if responses.is_empty() {
            return Err(Error::Other(
                "No responses to find consensus from".to_string(),
            ));
        }

        // For now, just return the first successful response
        // In a full implementation, we'd find the most common response based on content hash
        for response in responses {
            if response.success {
                return Ok(response.clone());
            }
        }

        // If no successful responses, return the first one (will contain error info)
        Ok(responses[0].clone())
    }

    fn get_session_sig_by_url(
        &self,
        session_sigs: &SessionSignatures,
        url: &str,
    ) -> Result<SessionSignature> {
        if session_sigs.is_empty() {
            return Err(Error::Other("You must pass in sessionSigs".to_string()));
        }

        let session_sig = session_sigs.get(url).ok_or_else(|| {
            Error::Other(format!(
                "You passed sessionSigs but we could not find session sig for node {}",
                url
            ))
        })?;

        Ok(session_sig.clone())
    }

    // fn collect_signature_shares(
    //     &self,
    //     node_responses: &[NodeShare],
    // ) -> Result<Option<serde_json::Value>> {
    //     // Collect signature shares from successful responses
    //     let mut signature_groups = std::collections::HashMap::<String, Vec<Vec<u8>>>::new();

    //     for response in node_responses {
    //         if !response.success || response.signed_data.is_empty() {
    //             continue;
    //         }

    //         // Group signature shares by signature name
    //         for (sig_name, sig_data) in &response.signed_data {
    //             if let Some(signature_share) = sig_data.get("signatureShare") {
    //                 if let Some(share_hex) = signature_share.as_str() {
    //                     // Remove 0x prefix if present and decode hex
    //                     let share_hex = share_hex.strip_prefix("0x").unwrap_or(share_hex);
    //                     if let Ok(share_bytes) = hex::decode(share_hex) {
    //                         signature_groups
    //                             .entry(sig_name.clone())
    //                             .or_insert_with(Vec::new)
    //                             .push(share_bytes);
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     if signature_groups.is_empty() {
    //         return Ok(None);
    //     }

    //     // Combine signature shares for each signature name
    //     let mut combined_signatures = serde_json::Map::new();

    //     for (sig_name, shares) in signature_groups {
    //         if shares.len() < 2 {
    //             // Need at least 2 shares to combine
    //             continue;
    //         }

    //         match self.combine_bls_signature_shares(&shares) {
    //             Ok(combined_sig) => {
    //                 let combined_sig_hex = format!("0x{}", hex::encode(combined_sig));
    //                 combined_signatures
    //                     .insert(sig_name, serde_json::Value::String(combined_sig_hex));
    //             }
    //             Err(e) => {
    //                 warn!("Failed to combine signature shares for {}: {}", sig_name, e);
    //                 // Fallback to returning the shares as-is
    //                 let shares_json: Vec<_> = shares
    //                     .iter()
    //                     .map(|s| serde_json::Value::String(format!("0x{}", hex::encode(s))))
    //                     .collect();
    //                 combined_signatures.insert(sig_name, serde_json::Value::Array(shares_json));
    //             }
    //         }
    //     }

    //     if combined_signatures.is_empty() {
    //         Ok(None)
    //     } else {
    //         Ok(Some(serde_json::Value::Object(combined_signatures)))
    //     }
    // }

    fn combine_bls_signature_shares(&self, shares: &[String]) -> Result<Vec<u8>> {
        info!("Combining BLS signature shares: {:?}", shares);
        if shares.len() < 2 {
            return Err(Error::Other(
                "Need at least 2 signature shares to combine".to_string(),
            ));
        }

        // Convert byte vectors to SignatureShare objects
        let signature_shares: Result<Vec<_>> = shares
            .iter()
            .map(|share| {
                // Parse as BLS signature share using serde_json (like in lit-node)
                // First try to convert bytes to hex string if needed

                // Parse as JSON string like in lit-node implementation
                serde_json::from_str::<SignatureShare<Bls12381G2Impl>>(share)
                    .map_err(|e| Error::Other(format!("Failed to parse signature share: {}", e)))
            })
            .collect();

        let signature_shares = signature_shares?;

        // Use the from_shares method like in lit-node implementation
        match Signature::<Bls12381G2Impl>::from_shares(&signature_shares) {
            Ok(combined_signature) => {
                info!("Combined signature: {:?}", combined_signature);

                // The signature JSON will be a hex string, extract the hex part
                let signature_bytes = combined_signature.as_raw_value().to_bytes();
                let signature_bytes_ref = signature_bytes.as_ref();
                info!("Combined signature bytes: {:?}", signature_bytes_ref);
                Ok(signature_bytes_ref.to_vec())
            }
            Err(e) => Err(Error::Other(format!(
                "Failed to combine BLS signature shares: {}",
                e
            ))),
        }
    }
}
