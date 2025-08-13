use crate::config::LitNodeClientConfig;
use dashmap::DashMap;
use reqwest::Client;
use std::sync::Arc;

mod connect;
mod execute;
mod pkp;
mod state;

pub struct LitNodeClient {
    pub(crate) config: LitNodeClientConfig,
    pub(crate) http_client: Client,
    pub(crate) connection_state: Arc<DashMap<String, crate::types::NodeConnectionInfo>>,
    pub(crate) ready: bool,
    pub(crate) subnet_pub_key: Option<String>,
    pub(crate) network_pub_key: Option<String>,
    pub(crate) network_pub_key_set: Option<String>,
    pub(crate) hd_root_pubkeys: Option<Vec<String>>,
    pub(crate) latest_blockhash: Option<String>,
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
}
