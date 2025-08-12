use crate::{
    config::{LitNetwork, LitNodeClientConfig},
    error::{Error, Result},
    types::{
        AuthMethod, AuthSig, ConnectionState, GetPkpSessionSigsRequest, HandshakeRequest,
        HandshakeResponse, NodeConnectionInfo, ResourceAbilityRequest, SessionSignatures,
    },
};
use dashmap::DashMap;
use rand::Rng;
use reqwest::Client;
use std::{
    collections::HashMap,
    sync::Arc,
};
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
        info!("Starting connection to Lit Network: {:?}", self.config.lit_network);
        
        // Get bootstrap URLs
        let bootstrap_urls = self.get_bootstrap_urls().await?;
        
        if bootstrap_urls.is_empty() {
            return Err(Error::Other("No bootstrap URLs found".to_string()));
        }
        
        info!("Found {} bootstrap URLs", bootstrap_urls.len());
        
        // Run handshake with nodes
        let min_node_count = self.config.min_node_count.unwrap_or(2);
        self.handshake_with_nodes(bootstrap_urls, min_node_count).await?;
        
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
                    "http://207.244.70.36:8473".to_string(),
                    "http://207.244.70.36:8474".to_string(),
                    "http://207.244.70.36:8475".to_string(),
                ])
            }
            _ => {
                // For other networks, fetch from staking contract
                self.fetch_validator_urls().await
            }
        }
    }

    async fn fetch_validator_urls(&self) -> Result<Vec<String>> {
        let _rpc_url = self.config.rpc_url.as_deref()
            .or_else(|| self.config.lit_network.rpc_url())
            .ok_or_else(|| Error::Other("No RPC URL configured".to_string()))?;
            
        let _staking_address = self.config.lit_network.staking_contract_address()
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
                .send()
        )
        .await
        .map_err(|_| Error::ConnectionTimeout)?
        .map_err(Error::Network)?;
        
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Unable to read body".to_string());
            warn!("Handshake failed with status {}: {}", status, body);
            return Err(Error::HandshakeFailed {
                url: url.to_string(),
                reason: format!("HTTP {} - {}", status, body),
            });
        }
        
        let body_text = response.text().await.map_err(Error::Network)?;
        info!("Handshake response body: {}", body_text);
        
        let handshake_response: HandshakeResponse = serde_json::from_str(&body_text)
            .map_err(|e| {
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
        let responses: Vec<HandshakeResponse> = self.connection_state
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
        let connected_nodes: Vec<String> = self.connection_state
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
        capability_auth_sigs: Vec<AuthSig>,
        auth_methods: Vec<AuthMethod>,
        resource_ability_requests: Vec<ResourceAbilityRequest>,
        expiration: &str,
    ) -> Result<SessionSignatures> {
        if !self.ready {
            return Err(Error::Other("Client not connected".to_string()));
        }

        let request = GetPkpSessionSigsRequest {
            pkp_public_key: pkp_public_key.to_string(),
            capability_auth_sigs,
            auth_methods,
            resource_ability_requests,
            expiration: expiration.to_string(),
        };

        // Send to all connected nodes and collect responses
        let mut session_sigs = HashMap::new();
        
        for node_url in self.connected_nodes() {
            match self.send_pkp_session_sig_request(&node_url, &request).await {
                Ok(node_session_sigs) => {
                    for (key, sig) in node_session_sigs {
                        session_sigs.insert(key, sig);
                    }
                }
                Err(e) => {
                    warn!("Failed to get session sigs from node {}: {}", node_url, e);
                }
            }
        }

        if session_sigs.is_empty() {
            return Err(Error::Other("Failed to get session signatures from any node".to_string()));
        }

        Ok(session_sigs)
    }

    async fn send_pkp_session_sig_request(
        &self,
        node_url: &str,
        request: &GetPkpSessionSigsRequest,
    ) -> Result<SessionSignatures> {
        let endpoint = format!("{}/web/pkp/sign", node_url);
        let request_id = self.generate_request_id();

        info!("Sending PKP session sig request to {}", endpoint);

        let response = timeout(
            self.config.connect_timeout,
            self.http_client
                .post(&endpoint)
                .header("X-Request-Id", request_id)
                .json(request)
                .send()
        )
        .await
        .map_err(|_| Error::ConnectionTimeout)?
        .map_err(Error::Network)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Unable to read body".to_string());
            warn!("PKP session sig request failed with status {}: {}", status, body);
            return Err(Error::Other(format!("HTTP {} - {}", status, body)));
        }

        let session_sigs: SessionSignatures = response.json().await
            .map_err(Error::Network)?;

        Ok(session_sigs)
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
        ).await
    }
}