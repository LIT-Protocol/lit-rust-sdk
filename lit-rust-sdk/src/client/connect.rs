// use crate::blockchain::Staking;
use crate::{
    blockchain::Staking,
    types::{HandshakeRequest, HandshakeResponse, NodeConnectionInfo},
};
use eyre::Result;
use rand::Rng;
use tracing::{info, warn};

impl<P: alloy::providers::Provider> super::LitNodeClient<P> {
    pub async fn connect(&mut self) -> Result<()> {
        info!(
            "Starting connection to Lit Network: {:?}",
            self.config.lit_network
        );

        // let _epoch = self.current_epoch_state().await?;
        // TODO: initialize the listener

        let network_info = self.get_network_info().await?;
        info!("Found network info: {:?}", network_info);

        let validators = network_info._2;
        let mut bootstrap_urls = Vec::with_capacity(validators.len());
        for validator in validators {
            let prefix = if validator.port == 443 {
                "https"
            } else {
                "http"
            };
            bootstrap_urls.push(format!("{}://{}:{}", prefix, validator.ip, validator.port));
        }

        let min_node_count = self.config.min_node_count.unwrap_or(2);
        self.handshake_with_nodes(bootstrap_urls, min_node_count)
            .await?;

        self.update_network_state_from_consensus();
        self.ready = true;
        info!("Successfully connected to Lit Network");
        Ok(())
    }

    async fn get_network_info(
        &self,
    ) -> Result<Staking::getActiveUnkickedValidatorStructsAndCountsReturn> {
        let network_info = self
            .staking
            .getActiveUnkickedValidatorStructsAndCounts()
            .call()
            .await?;
        Ok(network_info)
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
            return Err(eyre::eyre!(format!(
                "Not enough nodes connected. Connected: {}, Required: {}",
                successful_connections, min_count
            )));
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

        let response = self
            .http_client
            .post(&handshake_url)
            .header("X-Request-Id", request_id)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read body".to_string());
            warn!("Handshake failed with status {}: {}", status, body);
            return Err(eyre::eyre!(format!(
                "Handshake failed with status {}: {}",
                status, body
            )));
        }

        let body_text = response.text().await?;
        info!("Handshake response body: {}", body_text);

        let handshake_response: HandshakeResponse =
            serde_json::from_str(&body_text).map_err(|e| {
                warn!("Failed to parse handshake response: {}", e);
                eyre::eyre!(e)
            })?;
        Ok(handshake_response)
    }

    // async fn current_epoch_state(&self) -> Result<Staking::Epoch> {
    //     let epoch = self.staking.epoch().call().await?;
    //     epoch.
    //     Ok(epoch)
    // }

    fn generate_challenge(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        hex::encode(bytes)
    }

    pub(crate) fn generate_request_id(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        hex::encode(bytes)
    }

    pub(crate) fn update_network_state_from_consensus(&mut self) {
        let responses: Vec<HandshakeResponse> = self
            .connection_state
            .iter()
            .map(|entry| entry.handshake_response.clone())
            .collect();
        if responses.is_empty() {
            return;
        }
        let first = &responses[0];
        self.subnet_pub_key = Some(first.subnet_pub_key.clone());
        self.network_pub_key = Some(first.network_pub_key.clone());
        self.network_pub_key_set = Some(first.network_pub_key_set.clone());
        self.hd_root_pubkeys = Some(first.hd_root_pubkeys.clone());
        self.latest_blockhash = Some(first.latest_blockhash.clone());
    }
}
