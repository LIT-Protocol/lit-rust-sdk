use alloy::primitives::Address;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LitNetwork {
    DatilDev,
    DatilTest,
    Datil,
}

impl LitNetwork {
    pub fn staking_contract_address(&self) -> Result<Address> {
        match self {
            LitNetwork::DatilDev => {
                Ok("0xD4507CD392Af2c80919219d7896508728f6A623F".parse::<Address>()?)
            }
            LitNetwork::DatilTest => {
                Ok("0x5758aDa5a1dC05e659eF0B5062fbcF093Ec572D1".parse::<Address>()?)
            }
            LitNetwork::Datil => {
                Ok("0x21d636d95eE71150c0c3Ffa79268c989a329d1CE".parse::<Address>()?)
            }
        }
    }

    pub fn contract_resolver_address(&self) -> Result<Address> {
        match self {
            LitNetwork::DatilDev => {
                Ok("0xCF5d7074c722Dd044Dd45EC791942b881366627c".parse::<Address>()?)
            }
            LitNetwork::DatilTest => {
                Ok("0xCf908e1E4Ee79fb540e144C3EDB2796E8D413548".parse::<Address>()?)
            }
            LitNetwork::Datil => {
                Ok("0x5326a59fF2c41bCdA7E64F9afB9C313d0342117B".parse::<Address>()?)
            }
        }
    }

    pub fn rpc_url(&self) -> &'static str {
        match self {
            LitNetwork::DatilDev => "https://yellowstone-rpc.litprotocol.com/",
            LitNetwork::DatilTest => "https://yellowstone-rpc.litprotocol.com/",
            LitNetwork::Datil => "https://yellowstone-rpc.litprotocol.com/",
        }
    }

    pub fn env(&self) -> u8 {
        match self {
            LitNetwork::DatilDev => 0,
            LitNetwork::DatilTest => 0,
            LitNetwork::Datil => 2,
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
        }
    }
}
