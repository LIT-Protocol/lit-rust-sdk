mod contract_resolver;
mod pkp_nft;
mod rate_limit_nft;
pub mod staking;

pub use contract_resolver::ContractResolver;
use eyre::Result;
pub use pkp_nft::PKPNFT;
pub use rate_limit_nft::RateLimitNFT;
pub use staking::Staking;

use crate::LitNetwork;
use alloy::{
    primitives::{keccak256, Address, FixedBytes},
    providers::ProviderBuilder,
};

pub enum Contract {
    Staking,
    PKPNFT,
    RateLimitNFT,
    ContractResolver,
}

impl Contract {
    fn resolver_key(&self) -> FixedBytes<32> {
        match self {
            Contract::Staking => keccak256("STAKING"),
            Contract::PKPNFT => keccak256("PKP_NFT"),
            Contract::RateLimitNFT => keccak256("RATE_LIMIT_NFT"),
            Contract::ContractResolver => panic!("ContractResolver does not have a resolver key"),
        }
    }
}

pub async fn resolve_address(contract: Contract, lit_network: LitNetwork) -> Result<Address> {
    let provider = ProviderBuilder::new()
        .connect(lit_network.rpc_url())
        .await?;
    let contract_resolver =
        ContractResolver::new(lit_network.contract_resolver_address()?, provider);
    let resolver_key = contract.resolver_key();
    let resolved_address = contract_resolver
        .getContract(resolver_key, lit_network.env())
        .call()
        .await?;
    Ok(resolved_address)
}
