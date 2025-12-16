use alloy::{
    network::EthereumWallet, primitives::U256, providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use lit_rust_sdk::{
    blockchain::{resolve_address, Contract, PKPNFT},
    LitNetwork,
};
use std::str::FromStr;

#[tokio::test]
async fn test_mint_pkp() {
    tracing_subscriber::fmt::init();

    dotenv::from_path("../.env").ok();
    dotenv::from_path(".env").ok();

    let ethereum_private_key = std::env::var("ETHEREUM_PRIVATE_KEY")
        .expect("ETHEREUM_PRIVATE_KEY environment variable not set");

    let wallet =
        PrivateKeySigner::from_str(&ethereum_private_key).expect("Failed to parse private key");

    println!("Using wallet address: {}", wallet.address());

    let lit_network = LitNetwork::NagaTest;

    let pkp_nft_address = resolve_address(Contract::PKPNFT, lit_network)
        .await
        .expect("Failed to resolve PKP NFT contract address");

    println!("PKP NFT contract address: {}", pkp_nft_address);

    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(lit_network.rpc_url())
        .await
        .expect("Failed to connect to Ethereum network");

    let pkp_nft = PKPNFT::new(pkp_nft_address, provider.clone());

    let mint_cost = pkp_nft
        .mintCost()
        .call()
        .await
        .expect("Failed to get mint cost");

    println!("Mint cost: {} wei", mint_cost);

    let key_type = U256::from(2);

    println!("🔄 Minting PKP with key type: {}", key_type);

    let tx = pkp_nft.mintNext(key_type).value(mint_cost);

    let pending_tx = tx.send().await.expect("Failed to send mint transaction");

    println!("✅ Transaction sent: {}", pending_tx.tx_hash());
    println!("⏳ Waiting for transaction to be mined...");

    let receipt = pending_tx
        .get_receipt()
        .await
        .expect("Failed to get transaction receipt");

    println!("✅ Transaction mined!");
    println!("Transaction hash: {}", receipt.transaction_hash);
    println!("Block number: {:?}", receipt.block_number);
    println!("Gas used: {}", receipt.gas_used);

    let logs = receipt.logs();
    for log in logs {
        println!("Log topics: {:?}", log.topics());

        if log.topics().len() >= 4 {
            let token_id = U256::from_be_bytes(log.topics()[3].0);
            println!("✅ PKP NFT minted! Token ID: {}", token_id);

            let owner = pkp_nft
                .ownerOf(token_id)
                .call()
                .await
                .expect("Failed to get PKP owner");

            println!("PKP owner: {}", owner);
            assert_eq!(
                owner,
                wallet.address(),
                "PKP should be owned by the minting wallet"
            );

            let pkp_pub_key = pkp_nft
                .getPubkey(token_id)
                .call()
                .await
                .expect("Failed to get PKP public key");

            println!("PKP public key: 0x{}", hex::encode(&pkp_pub_key));

            let eth_address = pkp_nft
                .getEthAddress(token_id)
                .call()
                .await
                .expect("Failed to get PKP ETH address");

            println!("PKP ETH address: {}", eth_address);
        }
    }
}
