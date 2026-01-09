use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use lit_rust_sdk::{naga_dev, PkpMintManager};
use std::sync::Arc;

mod common;

use common::{acquire_pkp_mint_lock, get_eoa_private_key, get_rpc_url, store_cached_pkp};

#[tokio::test]
async fn test_mint_pkp() {
    let _ = dotenvy::dotenv();

    let rpc_url = match get_rpc_url() {
        Some(url) => url,
        None => {
            println!("Skipping test - no RPC URL configured");
            println!("Set LIT_RPC_URL in .env");
            return;
        }
    };

    let eoa_private_key = match get_eoa_private_key() {
        Some(key) => key,
        None => {
            println!("Skipping test - no EOA private key configured");
            println!("Set LIT_EOA_PRIVATE_KEY in .env");
            return;
        }
    };

    let wallet: LocalWallet = eoa_private_key
        .parse()
        .expect("Failed to parse private key");
    println!("Using wallet address: {}", wallet.address());

    // Create provider with signer
    let provider = Provider::<Http>::try_from(&rpc_url).expect("Failed to create provider");
    let chain_id = provider
        .get_chainid()
        .await
        .expect("Failed to get chain ID")
        .as_u64();
    println!("Chain ID: {}", chain_id);

    // Check wallet balance
    let balance = provider
        .get_balance(wallet.address(), None)
        .await
        .expect("Failed to get balance");
    println!("Wallet balance: {} wei", balance);

    let signer_wallet = wallet.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, signer_wallet));

    // Create PKP mint manager
    let config = naga_dev().with_rpc_url(rpc_url.clone());
    let mint_manager =
        PkpMintManager::new(&config, client.clone()).expect("Failed to create PkpMintManager");

    // Check mint cost first
    let pkp_nft_addr: Address = "0xB144B88514316a2f155D22937C76795b8fC9aDCd"
        .parse()
        .unwrap();
    println!("PKP NFT contract: {:?}", pkp_nft_addr);

    // Mint a PKP with key type 2 (ECDSA) and the default keyset
    println!("Minting PKP...");
    let key_type = U256::from(2); // ECDSA key type
    let key_set_id = "naga-keyset1";
    println!("Key type: {}, Key set ID: {}", key_type, key_set_id);

    let _mint_lock = acquire_pkp_mint_lock()
        .await
        .expect("Failed to acquire PKP mint lock");

    let mint_result = match mint_manager.mint_next(key_type, key_set_id).await {
        Ok(result) => result,
        Err(e) => {
            println!("Mint failed with error: {:?}", e);
            println!("This might be due to:");
            println!("  - Insufficient balance for mint cost");
            println!("  - Wrong chain ID (expected Lit Naga Dev chain)");
            println!("  - Contract issues");
            panic!("Failed to mint PKP: {:?}", e);
        }
    };

    println!("PKP minted successfully!");
    println!("Transaction hash: {:?}", mint_result.hash);
    println!("Block number: {:?}", mint_result.receipt.block_number);
    println!("Token ID: {}", mint_result.data.token_id);
    println!("Public key: {}", mint_result.data.pubkey);
    println!("ETH address: {:?}", mint_result.data.eth_address);
    let _ = store_cached_pkp(&mint_result.data.pubkey);

    // Verify the PKP data
    assert!(
        !mint_result.data.pubkey.is_empty(),
        "PKP should have a public key"
    );
    assert!(
        mint_result.data.token_id > U256::zero(),
        "PKP should have a valid token ID"
    );

    println!("Mint PKP test passed!");
    println!("\nTo use this PKP in other tests, set these environment variables:");
    println!("LIT_PKP_PUBLIC_KEY={}", mint_result.data.pubkey);
    println!("LIT_PKP_TOKEN_ID={}", mint_result.data.token_id);
}
