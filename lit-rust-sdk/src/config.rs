use alloy::primitives::Address;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LitNetwork {
    /// Naga Development network (Chronicle Yellowstone - Chain ID 175188)
    /// No attestation required
    NagaDev,
    /// Naga Test network (Chronicle Yellowstone - Chain ID 175188)
    NagaTest,
    /// Naga Staging network (Chronicle Yellowstone - Chain ID 175188)
    NagaStaging,
    /// Naga Proto network (Lit Chain - Chain ID 175200)
    NagaProto,
    /// Naga Mainnet (Lit Chain - Chain ID 175200)
    Naga,
}

impl LitNetwork {
    pub fn staking_contract_address(&self) -> Result<Address> {
        match self {
            LitNetwork::NagaDev => {
                Ok("0x544ac098670a266d3598B543aefBEbAb0A2C86C6".parse::<Address>()?)
            }
            LitNetwork::NagaTest => {
                Ok("0x9f3cE810695180C5f693a7cD2a0203A381fd57E1".parse::<Address>()?)
            }
            LitNetwork::NagaStaging => {
                Ok("0x9b8Ed3FD964Bc38dDc32CF637439e230CD50e3Dd".parse::<Address>()?)
            }
            LitNetwork::NagaProto => {
                Ok("0x28759afC5989B961D0A8EB236C9074c4141Baea1".parse::<Address>()?)
            }
            LitNetwork::Naga => {
                Ok("0x8a861B3640c1ff058CCB109ba11CA3224d228159".parse::<Address>()?)
            }
        }
    }

    pub fn contract_resolver_address(&self) -> Result<Address> {
        match self {
            LitNetwork::NagaDev => {
                Ok("0xd8e3AE077F1a9578Ad5f4E4b30DC3eC30b3f6bDD".parse::<Address>()?)
            }
            LitNetwork::NagaTest => {
                Ok("0x03aF23be3A816abd9aa5992434d42Bed1300eB03".parse::<Address>()?)
            }
            LitNetwork::NagaStaging => {
                Ok("0x7bcD366Dc0D3bc0AfAE0Aa78f96D5bf4999971c9".parse::<Address>()?)
            }
            LitNetwork::NagaProto => {
                Ok("0xf5d51a8A91152cA3b901d26528cfC21a4eC11fdF".parse::<Address>()?)
            }
            LitNetwork::Naga => {
                Ok("0x1f2cAA2976740cdb4cd8F98DA0c80f2FB0D8be72".parse::<Address>()?)
            }
        }
    }

    pub fn pkp_nft_address(&self) -> Result<Address> {
        match self {
            LitNetwork::NagaDev => {
                Ok("0xB144B88514316a2f155D22937C76795b8fC9aDCd".parse::<Address>()?)
            }
            LitNetwork::NagaTest => {
                Ok("0xaf4Dddb07Cdde48042e93eb5bf266b49950bC5BD".parse::<Address>()?)
            }
            LitNetwork::NagaStaging => {
                Ok("0x92d2a4Acb70E498a486E0523AD42fF3F6d3D3642".parse::<Address>()?)
            }
            LitNetwork::NagaProto => {
                Ok("0xaeEA5fE3654919c8Bb2b356aDCb5dF4eC082C168".parse::<Address>()?)
            }
            LitNetwork::Naga => {
                Ok("0x11eBfFeab32f6cb5775BeF83E09124B9322E4026".parse::<Address>()?)
            }
        }
    }

    pub fn pkp_permissions_address(&self) -> Result<Address> {
        match self {
            LitNetwork::NagaDev => {
                Ok("0x85Fa92469Ed765791818b17C926d29fA824E25Ca".parse::<Address>()?)
            }
            LitNetwork::NagaTest => {
                Ok("0x7255737630fCFb4914cF51552123eEe9abEc6120".parse::<Address>()?)
            }
            LitNetwork::NagaStaging => {
                Ok("0x1E382ef3957218423C6e1a992a4cE6294861cC93".parse::<Address>()?)
            }
            LitNetwork::NagaProto => {
                Ok("0x3894cae120A6ca08150e6e51cBcBdD5c16115F9c".parse::<Address>()?)
            }
            LitNetwork::Naga => {
                Ok("0xEB1F9A8567bC01b8cfa9d6e7078bEf587D908342".parse::<Address>()?)
            }
        }
    }

    pub fn pkp_helper_v2_address(&self) -> Result<Address> {
        match self {
            LitNetwork::NagaDev => {
                Ok("0x947c30CD7567AFD780F4a9E86fE703f6027d6dc0".parse::<Address>()?)
            }
            LitNetwork::NagaTest => {
                Ok("0x162AD624a82a41E2e49708eC1e57dBA8FC60907e".parse::<Address>()?)
            }
            LitNetwork::NagaStaging => {
                Ok("0xf56924352E374D4e66C79CE1d4b89563B6859416".parse::<Address>()?)
            }
            LitNetwork::NagaProto => {
                Ok("0x16D19021102928E52887A0166B013C36ca03A9Ce".parse::<Address>()?)
            }
            LitNetwork::Naga => {
                Ok("0x2B0F165965f63800F3c4c7e226E6411cc42729a8".parse::<Address>()?)
            }
        }
    }

    pub fn rpc_url(&self) -> &'static str {
        match self {
            // Chronicle Yellowstone networks
            LitNetwork::NagaDev | LitNetwork::NagaTest | LitNetwork::NagaStaging => {
                "https://yellowstone-rpc.litprotocol.com/"
            }
            // Lit Chain networks
            LitNetwork::NagaProto | LitNetwork::Naga => "https://lit-chain-rpc.litprotocol.com/",
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            // Chronicle Yellowstone
            LitNetwork::NagaDev | LitNetwork::NagaTest | LitNetwork::NagaStaging => 175188,
            // Lit Chain
            LitNetwork::NagaProto | LitNetwork::Naga => 175200,
        }
    }

    /// Returns whether attestation is required for this network
    pub fn requires_attestation(&self) -> bool {
        match self {
            LitNetwork::NagaDev => false,
            LitNetwork::NagaTest
            | LitNetwork::NagaStaging
            | LitNetwork::NagaProto
            | LitNetwork::Naga => true,
        }
    }

    /// Returns the network name as used in API requests
    pub fn network_name(&self) -> &'static str {
        match self {
            LitNetwork::NagaDev => "naga-dev",
            LitNetwork::NagaTest => "naga-test",
            LitNetwork::NagaStaging => "naga-staging",
            LitNetwork::NagaProto => "naga-proto",
            LitNetwork::Naga => "naga",
        }
    }

    /// Returns the environment number for the contract resolver
    /// Each Naga network has its own isolated contract resolver, so env is 0 for all
    pub fn env(&self) -> u8 {
        match self {
            LitNetwork::NagaDev => 0,
            LitNetwork::NagaTest => 0,
            LitNetwork::NagaStaging => 0,
            LitNetwork::NagaProto => 0,
            LitNetwork::Naga => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LitNodeClientConfig {
    pub lit_network: LitNetwork,
    pub alert_when_unauthorized: bool,
    pub debug: bool,
    pub connect_timeout: Duration,
    pub check_node_attestation: bool,
}

impl Default for LitNodeClientConfig {
    fn default() -> Self {
        Self {
            lit_network: LitNetwork::NagaDev,
            alert_when_unauthorized: true,
            debug: false,
            connect_timeout: Duration::from_millis(20000),
            check_node_attestation: false,
        }
    }
}
