use crate::{
    config::{LitNetwork, LitNodeClientConfig},
    error::{Error, Result},
    types::{
        AuthMethod, AuthSig, ConnectionState, ExecuteJsParams, ExecuteJsResponse, HandshakeRequest,
        HandshakeResponse, JsonSignSessionKeyResponseV1, LitResourceAbilityRequest,
        NodeConnectionInfo, NodeShare, SessionKeySignedMessage, SessionSignature,
        SessionSignatures, SignSessionKeyRequest, SignedData,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use blsful::{Bls12381G2Impl, Signature, SignatureShare};
use elliptic_curve::{scalar::IsHigh, subtle::ConditionallySelectable, PrimeField};
use dashmap::DashMap;
use ed25519_dalek::Signer;
use ethers::types::Address;
use k256::{Scalar, AffinePoint, ProjectivePoint};
use rand::Rng;
use reqwest::Client;
use serde_json::Value;
use siwe::Message;
use siwe_recap::Capability;
use std::ops::{Add, Sub};
use std::{collections::HashMap, sync::Arc};
use tokio::time::timeout;
use tracing::{debug, info, warn};

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
        resource_ability_requests: Vec<LitResourceAbilityRequest>,
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

        info!("Delegation auth sig: {:?}", delegation_auth_sig);

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
                node_address: node_url.to_owned(),
            };

            // Serialize to JSON
            let message =
                serde_json::to_string(&session_key_signed_message).map_err(Error::Serialization)?;

            // Sign with session key
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
        // Use PKP ETH address instead of capacity auth sig address
        let address = self.to_checksum_address(pkp_eth_address)?;
        info!("Using PKP ETH address for SIWE message: {}", address);

        // Fetch the latest Ethereum block hash to use as nonce
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

        let shares = parsed_responses
            .iter()
            .map(|response| {
                let sig_share = response.signature_share.clone();
                sig_share
            })
            .collect::<Vec<SignatureShare<Bls12381G2Impl>>>();

        let signature = match Signature::from_shares(&shares) {
            Ok(s) => s,
            Err(e) => {
                return Err(Error::Other(format!(
                    "Failed to combine BLS signature shares: {}",
                    e
                )));
            }
        };

        let bls_root_key = blsful::PublicKey::<Bls12381G2Impl>::try_from(
            &hex::decode(&one_response_with_share.bls_root_pubkey)
                .expect("Failed to decode root key"),
        )
        .expect("Failed to convert bls public key from bytes");
        let _ = signature
            .verify(
                &bls_root_key,
                hex::decode(&one_response_with_share.data_signed)
                    .expect("Could not decode data_signed")
                    .as_slice(),
            )
            .expect("Failed to verify signature when getting delegation signature from PKP and locally checking against the root key");

        let serialized_signature = match serde_json::to_string(&signature) {
            Ok(s) => s,
            Err(e) => panic!("Failed to serialize signature: {:?}", e),
        };

        Ok(AuthSig {
            sig: serialized_signature,
            derived_via: "lit.bls".to_string(),
            signed_message: one_response_with_share.siwe_message.clone(),
            address: self.to_checksum_address(pkp_eth_address)?,
            algo: Some("LIT_BLS".to_string()),
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

        // Create futures for all node requests
        let node_urls = self.connected_nodes();
        let min_responses = node_urls.len() * 2 / 3; // Require 2/3 responses

        let http_client = &self.http_client;
        let connect_timeout = self.config.connect_timeout;

        // Create a future for each node request
        let futures: Vec<_> = node_urls
            .iter()
            .map(|node_url| {
                let node_url = node_url.clone();
                let params = params.clone();
                let request_id = request_id.clone();
                async move {
                    let result = Self::execute_js_node_request(
                        http_client,
                        connect_timeout,
                        &node_url,
                        &params,
                        &request_id,
                    )
                    .await;
                    (node_url, result)
                }
            })
            .collect();

        // Execute all requests in parallel
        let results = futures::future::join_all(futures).await;

        // Collect successful responses
        let mut node_responses = Vec::new();
        for (node_url, result) in results {
            match result {
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

        // Combine ECDSA signature shares from all nodes
        let combined_signatures = self.combine_ecdsa_signature_shares(&node_responses).await?;

        Ok(ExecuteJsResponse {
            claims: most_common_response.claim_data,
            signatures: combined_signatures,
            decryptions: vec![],
            response: most_common_response.response,
            logs: most_common_response.logs,
        })
    }

    async fn execute_js_node_request(
        http_client: &Client,
        connect_timeout: std::time::Duration,
        node_url: &str,
        params: &ExecuteJsParams,
        request_id: &str,
    ) -> Result<NodeShare> {
        let endpoint = format!("{}/web/execute", node_url);

        // Get the session signature for this specific node URL
        let session_sig = Self::get_session_sig_by_url(&params.session_sigs, node_url)?;

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

        debug!("Sending execute request to {}: {}", endpoint, request_body);

        let response = timeout(
            connect_timeout,
            http_client
                .post(&endpoint)
                .header("X-Request-Id", request_id)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
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

    async fn combine_ecdsa_signature_shares(
        &self,
        node_responses: &[NodeShare],
    ) -> Result<Option<serde_json::Value>> {
        // Group signature shares by signature name
        let mut signatures_by_name: HashMap<String, Vec<SignedData>> = HashMap::new();

        for response in node_responses {
            if !response.success {
                continue;
            }

            for (_key, signed_data) in &response.signed_data {
                let sig_name = signed_data.sig_name.clone();
                signatures_by_name
                    .entry(sig_name)
                    .or_insert_with(Vec::new)
                    .push(signed_data.clone());
            }
        }

        if signatures_by_name.is_empty() {
            return Ok(None);
        }

        let mut combined_signatures = HashMap::new();

        for (sig_name, sig_shares) in signatures_by_name {
            // We need at least threshold signatures (2/3 for most cases)
            let threshold = self.connected_nodes().len() * 2 / 3;
            if sig_shares.len() < threshold {
                warn!(
                    "Not enough signature shares for {}. Got {}, need {}",
                    sig_name,
                    sig_shares.len(),
                    threshold
                );
                continue;
            }

            // Check if all shares have valid data
            let first_share = &sig_shares[0];
            if first_share.sig_type != "K256" {
                warn!("Unsupported signature type: {}", first_share.sig_type);
                continue;
            }

            // Check if this is a failed signature (dataSigned == "fail")
            // It's expected that some nodes will fail, so we only skip if we can't get threshold
            let valid_shares: Vec<_> = sig_shares.iter()
                .filter(|share| share.data_signed != "fail" && !share.signature_share.is_empty())
                .cloned()
                .collect();
            
            if valid_shares.len() < threshold {
                warn!(
                    "Not enough valid signature shares for {}. Got {} valid shares (total {}), need {}",
                    sig_name, valid_shares.len(), sig_shares.len(), threshold
                );
                continue;
            }
            
            info!(
                "Processing {} with {} valid shares out of {} total (threshold: {})", 
                sig_name, valid_shares.len(), sig_shares.len(), threshold
            );
            
            let first_share = &valid_shares[0];

            // Parse signature shares for combination
            let mut parsed_shares = Vec::new();
            let mut public_key = None;
            let mut presignature_big_r = None;
            let mut msg_hash = None;

            for share in &valid_shares {
                // Parse signature share
                let sig_share: Result<Scalar> = serde_json::from_str(&share.signature_share)
                    .map_err(|e| Error::Other(format!("Failed to parse signature share: {}", e)));

                if let Ok(sig_share) = sig_share {
                    parsed_shares.push(sig_share);

                    // Set common values from first valid share
                    if public_key.is_none() {
                        public_key =
                            serde_json::from_str::<k256::AffinePoint>(&share.public_key).ok();
                        presignature_big_r =
                            serde_json::from_str::<k256::AffinePoint>(&share.big_r).ok();
                        msg_hash = serde_json::from_str::<Scalar>(&share.data_signed).ok();
                    }
                }
            }

            // Combine the signature shares if we have enough valid ones
            if parsed_shares.len() >= threshold {
                if let (Some(pub_key), Some(big_r), Some(hash)) =
                    (public_key, presignature_big_r, msg_hash)
                {
                    // Use elliptic_curve/k256 to combine the signature shares
                    match self.combine_signature_shares_k256(parsed_shares, big_r) {
                        Ok((s, was_flipped)) => {
                            // Verify the signature using ECDSA verification
                            if self.verify_signature(&pub_key, &hash, &big_r, &s) {
                                info!(
                                    "Successfully combined and verified signature for {}",
                                    sig_name
                                );

                                // Convert to proper SigResponse format matching JS SDK
                                let sig_json = self.convert_signature_to_response(
                                    &big_r, 
                                    &s, 
                                    was_flipped,
                                    &pub_key, 
                                    &hash, 
                                    &first_share
                                )?;

                                combined_signatures.insert(sig_name, sig_json);
                            } else {
                                warn!("Combined signature verification failed for {}", sig_name);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to combine signature shares for {}: {:?}",
                                sig_name, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "Missing required data to combine signatures for {}",
                        sig_name
                    );
                }
            }
        }

        if combined_signatures.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::to_value(combined_signatures).unwrap()))
        }
    }

    /// Combine signature shares using k256/elliptic_curve, following JS SDK implementation
    fn combine_signature_shares_k256(
        &self,
        signature_shares: Vec<Scalar>,
        _big_r: AffinePoint,
    ) -> Result<(Scalar, bool)> {
        if signature_shares.is_empty() {
            return Err(Error::Other("No signature shares provided".to_string()));
        }
        
        // Sum all signature shares (equivalent to JS SDK's sum_scalars)
        let mut s: Scalar = signature_shares.into_iter().sum();
        
        // Apply low-s rule (normalize s to lower half of curve order)
        let was_flipped = s.is_high().into();
        s.conditional_assign(&(-s), s.is_high());
        
        Ok((s, was_flipped))
    }
    
    /// Verify ECDSA signature using k256
    fn verify_signature(
        &self,
        public_key: &AffinePoint,
        msg_hash: &Scalar,
        big_r: &AffinePoint,
        s: &Scalar,
    ) -> bool {
        use elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        
        // Extract r coordinate from big_r point
        let r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&big_r.x());
        
        if r.is_zero().into() || s.is_zero().into() {
            return false;
        }
        
        // Compute s_inv
        let s_inv = match Option::<Scalar>::from(s.invert()) {
            Some(inv) => inv,
            None => return false,
        };
        
        if msg_hash.is_zero().into() {
            return false;
        }
        
        // Verify: R = (z/s)G + (r/s)Y
        let public_key_proj = ProjectivePoint::from(*public_key);
        let generator = ProjectivePoint::GENERATOR;
        
        let reproduced = (generator * (*msg_hash * s_inv)) + (public_key_proj * (r * s_inv));
        let reproduced_affine = reproduced.to_affine();
        let reproduced_r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&reproduced_affine.x());
        
        reproduced_r == r
    }
    
    /// Convert signature to JS SDK format
    fn convert_signature_to_response(
        &self,
        big_r: &AffinePoint,
        s: &Scalar,
        was_flipped: bool,
        _public_key: &AffinePoint,
        _msg_hash: &Scalar,
        first_share: &SignedData,
    ) -> Result<serde_json::Value> {
        use elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        
        // Extract r from big_r point
        let r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&big_r.x());
        let r_bytes = r.to_repr();
        let r_hex = hex::encode(r_bytes);
        
        // Convert s to hex
        let s_bytes = s.to_repr();
        let s_hex = hex::encode(s_bytes);
        
        // Calculate recovery ID (v)
        let mut recid = if big_r.y_is_odd().into() { 1u8 } else { 0u8 };
        
        // Flip recovery ID if s was normalized (low-s rule)
        if was_flipped {
            recid = 1 - recid;
        }
        
        // Create the full signature hex (r + s with 0x prefix)
        let signature_hex = format!("0x{}{}", r_hex, s_hex);
        
        // Remove 0x prefix from public key if present and ensure proper format
        let public_key_clean = first_share.public_key
            .strip_prefix("0x")
            .unwrap_or(&first_share.public_key)
            .to_string();
        
        info!(
            "Converted signature for {}: r={}, s={}, recid={}, verified=true", 
            first_share.sig_name, 
            &r_hex[..16], // Show first 16 chars of r
            &s_hex[..16], // Show first 16 chars of s
            recid
        );
        
        Ok(serde_json::json!({
            "r": r_hex,
            "s": s_hex,
            "recid": recid,
            "signature": signature_hex,
            "publicKey": public_key_clean,
            "dataSigned": first_share.data_signed.clone(),
        }))
    }
}
