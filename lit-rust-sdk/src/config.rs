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
            LitNetwork::DatilDev => Some("0xD80149f66cC88d8C8AFf84a87331Ec392c979E5f"),
            LitNetwork::DatilTest => Some("0x3e8201Ba1239E6784cEc1B96EdadB3d01E69A493"),
            LitNetwork::Datil => Some("0x3e8201Ba1239E6784cEc1B96EdadB3d01E69A493"),
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
