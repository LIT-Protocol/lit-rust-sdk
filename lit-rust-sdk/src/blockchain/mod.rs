use crate::LitNetwork;
use ethers::{
    prelude::{Http, Provider, SignerMiddleware},
    signers::{LocalWallet, Signer, Wallet},
    types::H160,
};
use k256::ecdsa::SigningKey;
use staking::Staking;
use std::sync::Arc;
use url::Url;

pub mod staking;

pub fn staking_contract(
    network: LitNetwork,
    chain_id: u64,
    signing_key: SigningKey,
) -> ::ethers::contract::builders::ContractCall<
    SignerMiddleware<Provider<Http>, Wallet<SigningKey>>,
    [u8; 32],
> {
    let rpc_url = network.rpc_url().expect("network rpc_url is missing");
    let url = Url::parse(rpc_url).expect("url is invalid");
    let provider: Provider<Http> =
        Provider::new(Http::new_with_client(url, reqwest_legacy::Client::new()));
    let wallet = LocalWallet::from(signing_key).with_chain_id(chain_id);
    let sm = Arc::new(SignerMiddleware::new(provider, wallet));
    let contract_address: H160 = network
        .staking_contract_address()
        .expect("network missing staking contract address")
        .parse()
        .expect("invalid address");
    Staking::new(contract_address, sm)
        .method_hash([218, 25, 221, 251], ())
        .expect("method not found (this should never happen)")
}
