use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use lit_rust_sdk::{naga_dev, MintPkpTx, PkpMintManager};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::time::sleep;

static MINTED_PKP: OnceLock<String> = OnceLock::new();

pub fn get_rpc_url() -> Option<String> {
    env::var("LIT_RPC_URL")
        .or_else(|_| env::var("LIT_TXSENDER_RPC_URL"))
        .or_else(|_| env::var("LIT_YELLOWSTONE_PRIVATE_RPC_URL"))
        .or_else(|_| env::var("LOCAL_RPC_URL"))
        .ok()
}

fn normalize_0x_hex(s: String) -> String {
    if s.starts_with("0x") {
        s
    } else {
        format!("0x{s}")
    }
}

pub fn get_eoa_private_key() -> Option<String> {
    env::var("LIT_EOA_PRIVATE_KEY")
        .or_else(|_| env::var("ETHEREUM_PRIVATE_KEY"))
        .or_else(|_| env::var("LIVE_MASTER_ACCOUNT"))
        .or_else(|_| env::var("LOCAL_MASTER_ACCOUNT"))
        .ok()
        .map(normalize_0x_hex)
}

fn cache_paths() -> (PathBuf, PathBuf) {
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
    let cache_path = target_dir.join("pkp_cache.txt");
    let lock_path = target_dir.join("pkp_cache.lock");
    (cache_path, lock_path)
}

fn read_cached_pkp(path: &Path) -> Option<String> {
    let pkp = fs::read_to_string(path).ok()?;
    let pkp = pkp.trim().to_string();
    if pkp.is_empty() {
        None
    } else {
        Some(pkp)
    }
}

pub fn store_cached_pkp(pkp: &str) -> io::Result<()> {
    let (cache_path, _) = cache_paths();
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(cache_path, pkp)?;
    let _ = MINTED_PKP.set(pkp.to_string());
    Ok(())
}

pub struct PkpMintLock {
    path: PathBuf,
}

impl Drop for PkpMintLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub async fn acquire_pkp_mint_lock() -> io::Result<PkpMintLock> {
    let (_, lock_path) = cache_paths();
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let start = Instant::now();
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => return Ok(PkpMintLock { path: lock_path }),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                if start.elapsed() > Duration::from_secs(120) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for PKP mint lock",
                    ));
                }
                sleep(Duration::from_millis(500)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn mint_pkp(rpc_url: &str, eoa_private_key: &str) -> MintPkpTx {
    let wallet: LocalWallet = eoa_private_key
        .parse()
        .expect("Failed to parse private key");

    let provider = Provider::<Http>::try_from(rpc_url).expect("Failed to create provider");
    let chain_id = provider
        .get_chainid()
        .await
        .expect("Failed to get chain ID")
        .as_u64();
    let signer_wallet = wallet.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, signer_wallet));

    let config = naga_dev().with_rpc_url(rpc_url.to_string());
    let mint_manager =
        PkpMintManager::new(&config, client).expect("Failed to create PkpMintManager");

    let key_type = U256::from(2); // ECDSA
    let key_set_id = "naga-keyset1";

    mint_manager
        .mint_next(key_type, key_set_id)
        .await
        .expect("Failed to mint PKP")
}

pub async fn get_or_mint_pkp(rpc_url: &str, eoa_private_key: &str) -> String {
    if let Ok(pkp) = env::var("LIT_PKP_PUBLIC_KEY").or_else(|_| env::var("PKP_PUBLIC_KEY")) {
        println!("Using existing PKP from environment: {}...", &pkp[..20]);
        return pkp;
    }

    if let Some(pkp) = MINTED_PKP.get() {
        println!("Using cached minted PKP: {}...", &pkp[..20]);
        return pkp.clone();
    }

    let (cache_path, _) = cache_paths();
    if let Some(pkp) = read_cached_pkp(&cache_path) {
        println!("Using cached PKP from disk: {}...", &pkp[..20]);
        let _ = MINTED_PKP.set(pkp.clone());
        return pkp;
    }

    let _mint_lock = acquire_pkp_mint_lock()
        .await
        .expect("Failed to acquire PKP mint lock");

    if let Some(pkp) = read_cached_pkp(&cache_path) {
        println!("Using cached PKP from disk: {}...", &pkp[..20]);
        let _ = MINTED_PKP.set(pkp.clone());
        return pkp;
    }

    println!("No PKP in environment or cache, minting a new one...");
    let mint_result = mint_pkp(rpc_url, eoa_private_key).await;
    let pkp = mint_result.data.pubkey.clone();
    println!("Minted new PKP: {}", pkp);
    let _ = store_cached_pkp(&pkp);
    pkp
}
