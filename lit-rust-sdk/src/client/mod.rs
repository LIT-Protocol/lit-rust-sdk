use crate::config::LitNodeClientConfig;
use alloy::providers::{DynProvider, Provider as ProviderTrait, ProviderBuilder};
use dashmap::DashMap;
use eyre::Result;
use reqwest::Client;
use std::sync::Arc;

mod connect;
mod execute;
mod pkp;
mod session_sigs;
mod state;

use crate::blockchain::staking::LibStakingStorage::Epoch;
use crate::blockchain::Staking;

pub struct LitNodeClient<P = DynProvider>
where
    P: ProviderTrait,
{
    pub(crate) config: LitNodeClientConfig,
    pub(crate) http_client: Client,
    pub(crate) connection_state: Arc<DashMap<String, crate::types::NodeConnectionInfo>>,
    pub(crate) ready: bool,
    pub(crate) subnet_pub_key: Option<String>,
    pub(crate) network_pub_key: Option<String>,
    pub(crate) network_pub_key_set: Option<String>,
    pub(crate) hd_root_pubkeys: Option<Vec<String>>,
    pub(crate) latest_blockhash: Option<String>,
    pub(crate) staking: Staking::StakingInstance<P>,
    pub(crate) min_node_count: Option<usize>,
    pub(crate) epoch: Option<Epoch>,
}

impl LitNodeClient<DynProvider> {
    pub async fn new(config: LitNodeClientConfig) -> Result<Self> {
        let http_client = Client::builder().timeout(config.connect_timeout).build()?;

        let rpc_url = config.lit_network.rpc_url();
        let provider = ProviderBuilder::new().connect(rpc_url).await?;
        let staking_address = config.lit_network.staking_contract_address()?;

        let staking = Staking::new(staking_address, provider.erased());

        Ok(Self {
            config,
            http_client,
            connection_state: Arc::new(DashMap::new()),
            ready: false,
            subnet_pub_key: None,
            network_pub_key: None,
            network_pub_key_set: None,
            hd_root_pubkeys: None,
            latest_blockhash: None,
            staking,
            min_node_count: None,
            epoch: None,
        })
    }
}
