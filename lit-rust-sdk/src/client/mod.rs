use crate::config::LitNodeClientConfig;
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider as ProviderTrait, ProviderBuilder},
};
use dashmap::DashMap;
use eyre::Result;
use reqwest::Client;
use std::sync::Arc;

mod connect;
mod execute;
mod pkp;
mod state;

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
}

impl LitNodeClient<DynProvider> {
    pub async fn new(config: LitNodeClientConfig) -> Result<Self> {
        let http_client = Client::builder().timeout(config.connect_timeout).build()?;

        let rpc_url = match &config.rpc_url {
            Some(rpc_url) => rpc_url.clone(),
            None => match config.lit_network.rpc_url() {
                Some(rpc_url) => rpc_url.to_string(),
                None => {
                    return Err(eyre::eyre!(
                        "RPC url not found for lit network that was specified"
                    ));
                }
            },
        };

        let provider = ProviderBuilder::new().connect(&rpc_url).await?;
        let staking_address = match config.lit_network.staking_contract_address() {
            Some(staking_address) => staking_address,
            None => {
                return Err(eyre::eyre!(
                    "Staking contract address not found for lit network that was specified"
                ));
            }
        };

        let staking = Staking::new(staking_address.parse::<Address>()?, provider.erased());

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
        })
    }
}
