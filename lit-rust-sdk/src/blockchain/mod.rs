use crate::LitNetwork;
use ethers::{
    prelude::{Http, Provider},
    types::H160,
};
use staking::Staking;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub mod staking;

pub fn staking_contract(network: LitNetwork) -> Staking<Provider<Http>> {
    let contract_address: H160 = network
        .staking_contract_address()
        .expect("network missing staking contract address")
        .parse()
        .expect("invalid address");
    Staking::new(contract_address, default_local_client_no_wallet(network))
}

fn default_local_client_no_wallet(network: LitNetwork) -> Arc<Provider<Http>> {
    let client = reqwest_legacy::Client::builder()
        .timeout(Duration::from_secs(30))
        .use_rustls_tls()
        .build()
        .expect("could not build client");
    let url = Url::parse(network.rpc_url().expect("a valid rpc url")).expect("url is invalid");

    let mut provider = Provider::new(Http::new_with_client(url, client));
    provider.set_interval(Duration::from_secs(1));
    Arc::new(provider)
}
