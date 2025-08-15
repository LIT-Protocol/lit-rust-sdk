use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LitNetwork {
    DatilDev,
    DatilTest,
    Datil,
    Custom,
}

impl LitNetwork {
    pub fn staking_contract_address(&self) -> Option<&'static str> {
        match self {
            LitNetwork::DatilDev => Some("0xD4507CD392Af2c80919219d7896508728f6A623F"),
            LitNetwork::DatilTest => Some("0x5758aDa5a1dC05e659eF0B5062fbcF093Ec572D1"),
            LitNetwork::Datil => Some("0x21d636d95eE71150c0c3Ffa79268c989a329d1CE"),
            LitNetwork::Custom => None,
        }
    }

    pub fn rpc_url(&self) -> Option<&'static str> {
        match self {
            LitNetwork::DatilDev => Some("https://chain-rpc.litprotocol.com/http"),
            LitNetwork::DatilTest => Some("https://yellowstone-rpc.litprotocol.com/"),
            LitNetwork::Datil => Some("https://yellowstone-rpc.litprotocol.com/"),
            LitNetwork::Custom => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LitNodeClientConfig {
    pub lit_network: LitNetwork,
    pub alert_when_unauthorized: bool,
    pub min_node_count: Option<usize>,
    pub debug: bool,
    pub connect_timeout: Duration,
    pub check_node_attestation: bool,
    pub rpc_url: Option<String>,
}

impl Default for LitNodeClientConfig {
    fn default() -> Self {
        Self {
            lit_network: LitNetwork::DatilDev,
            alert_when_unauthorized: true,
            min_node_count: None,
            debug: false,
            connect_timeout: Duration::from_millis(20000),
            check_node_attestation: false,
            rpc_url: None,
        }
    }
}
