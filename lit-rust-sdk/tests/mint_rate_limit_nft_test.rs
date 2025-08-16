use alloy::{
    network::EthereumWallet, primitives::U256, providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use chrono::{Datelike, Duration, TimeZone, Utc};
use lit_rust_sdk::{
    blockchain::{resolve_address, Contract, RateLimitNFT},
    LitNetwork,
};
use std::str::FromStr;

#[tokio::test]
async fn test_mint_rate_limit_nft() {
    tracing_subscriber::fmt::init();

    dotenv::from_path("../.env").ok();
    dotenv::from_path(".env").ok();

    let ethereum_private_key = std::env::var("ETHEREUM_PRIVATE_KEY")
        .expect("ETHEREUM_PRIVATE_KEY environment variable not set");

    let wallet =
        PrivateKeySigner::from_str(&ethereum_private_key).expect("Failed to parse private key");

    println!("Using wallet address: {}", wallet.address());

    let lit_network = LitNetwork::DatilTest;

    let rate_limit_nft_address = resolve_address(Contract::RateLimitNFT, lit_network)
        .await
        .expect("Failed to resolve Rate Limit NFT contract address");

    println!(
        "Rate Limit NFT contract address: {}",
        rate_limit_nft_address
    );

    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(lit_network.rpc_url())
        .await
        .expect("Failed to connect to Ethereum network");

    let rate_limit_nft = RateLimitNFT::new(rate_limit_nft_address, provider.clone());

    // Calculate expiresAt: 20 days from now, at midnight UTC
    let now = Utc::now();
    let future_date = now + Duration::days(20);

    // Set to midnight UTC
    let midnight_date = Utc
        .with_ymd_and_hms(
            future_date.year(),
            future_date.month(),
            future_date.day(),
            0,
            0,
            0,
        )
        .single()
        .expect("Invalid date");

    let expires_at = U256::from(midnight_date.timestamp() as u64);
    let requests_per_kilosecond = U256::from(1000);

    println!(
        "🔄 Calculating cost for {} requests per kilosecond until {}",
        requests_per_kilosecond, midnight_date
    );

    // Calculate the exact cost needed
    let cost = rate_limit_nft
        .calculateCost(requests_per_kilosecond, expires_at)
        .call()
        .await
        .expect("Failed to calculate cost");

    println!("💰 Calculated cost: {} wei", cost);

    println!(
        "🔄 Minting Rate Limit NFT with expiresAt: {} ({})",
        expires_at, midnight_date
    );

    let tx = rate_limit_nft.mint(expires_at).value(cost);

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

        // Look for Transfer event (topic[0] = Transfer, topic[1] = from, topic[2] = to, topic[3] = tokenId)
        if log.topics().len() >= 4 {
            let token_id = U256::from_be_bytes(log.topics()[3].0);
            println!("✅ Rate Limit NFT minted! Token ID: {}", token_id);

            let owner = rate_limit_nft
                .ownerOf(token_id)
                .call()
                .await
                .expect("Failed to get Rate Limit NFT owner");

            println!("Rate Limit NFT owner: {}", owner);
            assert_eq!(
                owner,
                wallet.address(),
                "Rate Limit NFT should be owned by the minting wallet"
            );

            // Check token URI if available
            if let Ok(token_uri) = rate_limit_nft.tokenURI(token_id).call().await {
                println!("Token URI: {}", token_uri);
            }

            break;
        }
    }
}
