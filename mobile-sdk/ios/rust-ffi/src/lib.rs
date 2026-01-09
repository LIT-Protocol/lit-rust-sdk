use chrono::Utc;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, I256, U256};
use ethers::utils::{format_units, to_checksum};
use lit_rust_sdk::{
    create_eth_wallet_auth_data, create_lit_client, naga_dev, naga_local, naga_mainnet, naga_proto,
    naga_staging, naga_test, view_pkps_by_address, AuthConfig, AuthContext, LitAbility, LitClient,
    LitSdkError, NetworkConfig, Pagination, PaymentManager, PkpMintManager, ResourceAbilityRequest,
};
use serde_json::json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

#[repr(C)]
pub struct LitClientHandle {
    client: Arc<LitClient>,
    runtime: Runtime,
    config: NetworkConfig,
}

#[repr(C)]
pub struct LitAuthContextHandle {
    context: AuthContext,
}

fn network_config_from_str(network_name: &str) -> Result<NetworkConfig, LitSdkError> {
    match network_name {
        "naga-dev" => Ok(naga_dev()),
        "naga-test" => Ok(naga_test()),
        "naga-staging" => Ok(naga_staging()),
        "naga-proto" => Ok(naga_proto()),
        "naga" => Ok(naga_mainnet()),
        "naga-local" => Ok(naga_local()),
        _ => Err(LitSdkError::Config(format!(
            "unknown network: {}",
            network_name
        ))),
    }
}

fn chain_id_for_network(network_name: &str) -> Option<u64> {
    match network_name {
        "naga" => Some(175200),
        "naga-dev" | "naga-test" | "naga-staging" | "naga-proto" => Some(175188),
        "naga-local" => Some(31337),
        _ => None,
    }
}

fn parse_eth_address(address: &str) -> Result<Address, LitSdkError> {
    Address::from_str(address)
        .map_err(|e| LitSdkError::Config(format!("invalid address: {e}")))
}

fn format_ether(value: U256) -> String {
    format_units(value, 18).unwrap_or_else(|_| value.to_string())
}

fn format_ether_signed(value: I256) -> String {
    let (sign, abs) = value.into_sign_and_abs();
    let formatted = format_ether(abs);
    match sign {
        ethers::types::Sign::Negative => format!("-{}", formatted),
        _ => formatted,
    }
}

fn set_error_message(error_out: *mut *mut c_char, message: String) {
    if error_out.is_null() {
        return;
    }
    let c_str = CString::new(message)
        .unwrap_or_else(|_| CString::new("Failed to create error message").unwrap());
    unsafe {
        *error_out = c_str.into_raw();
    }
}

fn set_error(error_out: *mut *mut c_char, error: LitSdkError) {
    set_error_message(error_out, error.to_string());
}

fn set_result_message(result_out: *mut *mut c_char, message: String) {
    if result_out.is_null() {
        return;
    }
    let c_str = CString::new(message)
        .unwrap_or_else(|_| CString::new("Failed to create result string").unwrap());
    unsafe {
        *result_out = c_str.into_raw();
    }
}

#[no_mangle]
pub extern "C" fn lit_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn lit_client_create(
    network_name: *const c_char,
    rpc_url: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut LitClientHandle {
    if network_name.is_null() {
        set_error_message(error_out, "network_name is null".to_string());
        return ptr::null_mut();
    }

    let network_cstr = unsafe { CStr::from_ptr(network_name) };
    let network_str = match network_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid network name: {}", e));
            return ptr::null_mut();
        }
    };

    let mut config = match network_config_from_str(network_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_error(error_out, e);
            return ptr::null_mut();
        }
    };

    if !rpc_url.is_null() {
        let rpc_cstr = unsafe { CStr::from_ptr(rpc_url) };
        let rpc_str = match rpc_cstr.to_str() {
            Ok(s) => s,
            Err(e) => {
                set_error_message(error_out, format!("Invalid rpc_url: {}", e));
                return ptr::null_mut();
            }
        };
        if !rpc_str.is_empty() {
            config = config.with_rpc_url(rpc_str.to_string());
        }
    }

    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            set_error_message(error_out, format!("Failed to create runtime: {}", e));
            return ptr::null_mut();
        }
    };

    let config_for_chain = config.clone();
    let client = match runtime.block_on(create_lit_client(config)) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            set_error(error_out, e);
            return ptr::null_mut();
        }
    };

    let handle = Box::new(LitClientHandle {
        client,
        runtime,
        config: config_for_chain,
    });
    Box::into_raw(handle)
}

#[no_mangle]
pub extern "C" fn lit_client_destroy(handle: *mut LitClientHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

#[no_mangle]
pub extern "C" fn lit_eoa_address_from_private_key(
    eoa_private_key: *const c_char,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if eoa_private_key.is_null() {
        set_error_message(error_out, "eoa_private_key is null".to_string());
        return 1;
    }

    let eoa_private_key = unsafe { CStr::from_ptr(eoa_private_key) };
    let eoa_private_key = match eoa_private_key.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_private_key: {}", e));
            return 1;
        }
    };

    let wallet: LocalWallet = match eoa_private_key.parse::<LocalWallet>() {
        Ok(w) => w,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_private_key: {}", e));
            return 1;
        }
    };

    let address = to_checksum(&wallet.address(), None);
    set_result_message(result_out, address);
    0
}

#[no_mangle]
pub extern "C" fn lit_auth_context_create(
    client_handle: *mut LitClientHandle,
    pkp_public_key: *const c_char,
    eoa_private_key: *const c_char,
    expiration_minutes: u32,
    error_out: *mut *mut c_char,
) -> *mut LitAuthContextHandle {
    if client_handle.is_null() {
        set_error_message(error_out, "client_handle is null".to_string());
        return ptr::null_mut();
    }
    if pkp_public_key.is_null() {
        set_error_message(error_out, "pkp_public_key is null".to_string());
        return ptr::null_mut();
    }
    if eoa_private_key.is_null() {
        set_error_message(error_out, "eoa_private_key is null".to_string());
        return ptr::null_mut();
    }

    let pkp_public_key = unsafe { CStr::from_ptr(pkp_public_key) };
    let pkp_public_key = match pkp_public_key.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid pkp_public_key: {}", e));
            return ptr::null_mut();
        }
    };

    let eoa_private_key = unsafe { CStr::from_ptr(eoa_private_key) };
    let eoa_private_key = match eoa_private_key.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_private_key: {}", e));
            return ptr::null_mut();
        }
    };

    let client = unsafe { &(*client_handle).client };
    let runtime = unsafe { &(*client_handle).runtime };

    let nonce = client
        .handshake_result()
        .core_node_config
        .latest_blockhash
        .clone();

    let auth_data = match runtime.block_on(create_eth_wallet_auth_data(eoa_private_key, &nonce)) {
        Ok(data) => data,
        Err(e) => {
            set_error(error_out, e);
            return ptr::null_mut();
        }
    };

    let minutes = if expiration_minutes == 0 {
        30
    } else {
        expiration_minutes
    };
    let expiration = (Utc::now() + chrono::Duration::minutes(minutes.into())).to_rfc3339();

    let auth_config = AuthConfig {
        capability_auth_sigs: vec![],
        expiration,
        statement: "Lit SDK iOS Demo - PKP signing".into(),
        domain: "localhost".into(),
        resources: vec![ResourceAbilityRequest {
            ability: LitAbility::PKPSigning,
            resource_id: "*".into(),
            data: None,
        }],
    };

    let auth_context = match runtime.block_on(client.create_pkp_auth_context(
        pkp_public_key,
        auth_data,
        auth_config,
        None,
        None,
        None,
    )) {
        Ok(ctx) => ctx,
        Err(e) => {
            set_error(error_out, e);
            return ptr::null_mut();
        }
    };

    let handle = Box::new(LitAuthContextHandle { context: auth_context });
    Box::into_raw(handle)
}

#[no_mangle]
pub extern "C" fn lit_auth_context_destroy(handle: *mut LitAuthContextHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

#[no_mangle]
pub extern "C" fn lit_view_pkps_by_address(
    client_handle: *mut LitClientHandle,
    eoa_address: *const c_char,
    limit: u32,
    offset: u32,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if client_handle.is_null() {
        set_error_message(error_out, "client_handle is null".to_string());
        return 1;
    }
    if eoa_address.is_null() {
        set_error_message(error_out, "eoa_address is null".to_string());
        return 1;
    }

    let eoa_address = unsafe { CStr::from_ptr(eoa_address) };
    let eoa_address = match eoa_address.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_address: {}", e));
            return 1;
        }
    };

    let address = match parse_eth_address(eoa_address) {
        Ok(addr) => addr,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let config = unsafe { &(*client_handle).config };
    let runtime = unsafe { &(*client_handle).runtime };

    let pagination = Pagination {
        limit: limit as usize,
        offset: offset as usize,
    };

    let pkps = match runtime.block_on(view_pkps_by_address(config, address, pagination)) {
        Ok(result) => result,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let pkps_json = pkps
        .pkps
        .iter()
        .map(|pkp| {
            json!({
                "tokenId": pkp.token_id.to_string(),
                "pubkey": pkp.pubkey,
                "ethAddress": to_checksum(&pkp.eth_address, None),
            })
        })
        .collect::<Vec<_>>();

    let result_json = json!({
        "pkps": pkps_json,
        "pagination": {
            "limit": pkps.pagination.limit,
            "offset": pkps.pagination.offset,
            "total": pkps.pagination.total,
            "hasMore": pkps.pagination.has_more,
        },
    });

    set_result_message(result_out, result_json.to_string());
    0
}

#[no_mangle]
pub extern "C" fn lit_mint_pkp_with_eoa(
    client_handle: *mut LitClientHandle,
    eoa_private_key: *const c_char,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if client_handle.is_null() {
        set_error_message(error_out, "client_handle is null".to_string());
        return 1;
    }
    if eoa_private_key.is_null() {
        set_error_message(error_out, "eoa_private_key is null".to_string());
        return 1;
    }

    let eoa_private_key = unsafe { CStr::from_ptr(eoa_private_key) };
    let eoa_private_key = match eoa_private_key.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_private_key: {}", e));
            return 1;
        }
    };

    let config = unsafe { &(*client_handle).config };
    let rpc_url = match config.rpc_url.as_deref() {
        Some(url) => url,
        None => {
            set_error_message(error_out, "rpc_url is required for minting".to_string());
            return 1;
        }
    };

    let provider = match Provider::<Http>::try_from(rpc_url) {
        Ok(p) => p,
        Err(e) => {
            set_error_message(error_out, format!("Failed to create provider: {}", e));
            return 1;
        }
    };

    let mut wallet: LocalWallet = match eoa_private_key.parse::<LocalWallet>() {
        Ok(w) => w,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_private_key: {}", e));
            return 1;
        }
    };

    if let Some(chain_id) = chain_id_for_network(config.network) {
        wallet = wallet.with_chain_id(chain_id);
    }

    let middleware = SignerMiddleware::new(provider, wallet);
    let manager = match PkpMintManager::new(config, Arc::new(middleware)) {
        Ok(m) => m,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let runtime = unsafe { &(*client_handle).runtime };
    let result = match runtime.block_on(manager.mint_with_eoa()) {
        Ok(minted) => minted,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let result_json = json!({
        "txHash": format!("{:#x}", result.hash),
        "data": {
            "tokenId": result.data.token_id.to_string(),
            "pubkey": result.data.pubkey,
            "ethAddress": to_checksum(&result.data.eth_address, None),
        }
    });

    set_result_message(result_out, result_json.to_string());
    0
}

#[no_mangle]
pub extern "C" fn lit_get_balances(
    client_handle: *mut LitClientHandle,
    eoa_address: *const c_char,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if client_handle.is_null() {
        set_error_message(error_out, "client_handle is null".to_string());
        return 1;
    }
    if eoa_address.is_null() {
        set_error_message(error_out, "eoa_address is null".to_string());
        return 1;
    }

    let eoa_address = unsafe { CStr::from_ptr(eoa_address) };
    let eoa_address = match eoa_address.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid eoa_address: {}", e));
            return 1;
        }
    };

    let address = match parse_eth_address(eoa_address) {
        Ok(addr) => addr,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let config = unsafe { &(*client_handle).config };
    let rpc_url = match config.rpc_url.as_deref() {
        Some(url) => url,
        None => {
            set_error_message(error_out, "rpc_url is required for balances".to_string());
            return 1;
        }
    };

    let provider = match Provider::<Http>::try_from(rpc_url) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            set_error_message(error_out, format!("Failed to create provider: {}", e));
            return 1;
        }
    };

    let runtime = unsafe { &(*client_handle).runtime };
    let native_balance = match runtime.block_on(provider.get_balance(address, None)) {
        Ok(balance) => balance,
        Err(e) => {
            set_error_message(error_out, format!("Failed to fetch native balance: {}", e));
            return 1;
        }
    };

    let payment_manager = match PaymentManager::new(config, provider) {
        Ok(manager) => manager,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let ledger_balance = match runtime.block_on(payment_manager.get_balance(address)) {
        Ok(balance) => balance,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let result_json = json!({
        "nativeBalanceWei": native_balance.to_string(),
        "nativeBalance": format_ether(native_balance),
        "ledgerTotalWei": ledger_balance.total_balance_wei.to_string(),
        "ledgerTotal": format_ether_signed(ledger_balance.total_balance_wei),
        "ledgerAvailableWei": ledger_balance.available_balance_wei.to_string(),
        "ledgerAvailable": format_ether_signed(ledger_balance.available_balance_wei),
    });

    set_result_message(result_out, result_json.to_string());
    0
}

#[no_mangle]
pub extern "C" fn lit_client_pkp_sign(
    client_handle: *mut LitClientHandle,
    pkp_public_key: *const c_char,
    message_ptr: *const u8,
    message_len: usize,
    auth_context_handle: *mut LitAuthContextHandle,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if client_handle.is_null() {
        set_error_message(error_out, "client_handle is null".to_string());
        return 1;
    }
    if pkp_public_key.is_null() {
        set_error_message(error_out, "pkp_public_key is null".to_string());
        return 1;
    }
    if message_ptr.is_null() {
        set_error_message(error_out, "message is null".to_string());
        return 1;
    }
    if auth_context_handle.is_null() {
        set_error_message(error_out, "auth_context_handle is null".to_string());
        return 1;
    }

    let pkp_public_key = unsafe { CStr::from_ptr(pkp_public_key) };
    let pkp_public_key = match pkp_public_key.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error_message(error_out, format!("Invalid pkp_public_key: {}", e));
            return 1;
        }
    };

    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    let auth_context = unsafe { &(*auth_context_handle).context };
    let client = unsafe { &(*client_handle).client };
    let runtime = unsafe { &(*client_handle).runtime };

    let signature = match runtime.block_on(client.pkp_sign_ethereum(
        pkp_public_key,
        message,
        auth_context,
        None,
    )) {
        Ok(sig) => sig,
        Err(e) => {
            set_error(error_out, e);
            return 1;
        }
    };

    let signature_json = match serde_json::to_string(&signature) {
        Ok(value) => value,
        Err(e) => {
            set_error_message(error_out, format!("Failed to serialize signature: {}", e));
            return 1;
        }
    };

    set_result_message(result_out, signature_json);
    0
}
