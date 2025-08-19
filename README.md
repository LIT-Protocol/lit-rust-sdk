# Lit Protocol Rust SDK

[![CI](https://github.com/LIT-Protocol/lit-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/LIT-Protocol/lit-rust-sdk/actions/workflows/ci.yml)
[![Documentation](https://docs.rs/lit-rust-sdk/badge.svg)](https://docs.rs/lit-rust-sdk/latest/lit_rust_sdk/)

A native Rust implementation of the Lit Protocol SDK, providing programmatic access to the Lit Network for distributed key management, conditional access control, and programmable signing.

Currently in Beta and only supports Datil, DatilDev, and DatilTest networks.

## Features

- **Local Session Signatures**: Execute Lit Actions using only your Ethereum wallet (no PKP required)
- **PKP Management**: Mint and manage Programmable Key Pairs (PKPs)
- **Session Signatures**: Generate and manage session signatures for authentication
- **Lit Actions**: Execute JavaScript code on the Lit Network with access to PKP signing capabilities
- **Capacity Delegation**: Delegate network capacity using Rate Limit NFTs
- **Multi-Network Support**: Connect to Datil, DatilDev, and DatilTest networks
- **Ethereum Wallet Integration**: Native support for Ethereum wallet authentication

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
lit-rust-sdk = "0.2.0"
tokio = { version = "1.40", features = ["full"] }
```

## Quick Start

### Basic Connection

```rust
use lit_rust_sdk::{LitNetwork, LitNodeClient, LitNodeClientConfig};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Configure the client
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    // Create and connect to the Lit Network
    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    client.connect().await.expect("Failed to connect");

    println!("Connected to {} nodes", client.connected_nodes().len());
}
```

### Executing a Lit Action (Simple Approach - No PKP Required)

For most use cases, you can execute Lit Actions using only your Ethereum wallet without needing to mint PKPs:

```rust
use lit_rust_sdk::{
    auth::load_wallet_from_env,
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig,
};
use std::time::Duration;

const HELLO_WORLD_LIT_ACTION: &str = r#"
const go = async () => {
  console.log("Hello from Lit Action!");
  Lit.Actions.setResponse({ response: "Hello World from Rust SDK!" });
};
go();
"#;

#[tokio::main]
async fn main() {
    // Load wallet from environment variable
    let wallet = load_wallet_from_env()
        .expect("Failed to load wallet from ETHEREUM_PRIVATE_KEY env var");

    // Configure and connect to Lit Network
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    client.connect().await.expect("Failed to connect");

    // Create resource ability requests for Lit Action execution
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    // Generate session signatures with your wallet (no PKP needed!)
    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
    let session_sigs = client
        .get_local_session_sigs(&wallet, resource_ability_requests, &expiration)
        .await
        .expect("Failed to create local session signatures");

    // Execute the Lit Action
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    let response = client
        .execute_js(execute_params)
        .await
        .expect("Failed to execute Lit Action");

    println!("Response: {:?}", response.response);
    println!("Logs: {}", response.logs);
}
```

### Executing a Lit Action (With PKP Signing)

```rust
use lit_rust_sdk::{
    auth::{load_wallet_from_env, EthWalletProvider},
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig,
};
use std::time::Duration;

const HELLO_WORLD_LIT_ACTION: &str = r#"
const go = async () => {
  console.log("Hello from Lit Action!");
  Lit.Actions.setResponse({ response: "Hello World!" });
};
go();
"#;

#[tokio::main]
async fn main() {
    // Load wallet from environment
    let wallet = load_wallet_from_env()
        .expect("Failed to load wallet");

    // Create and connect client
    let config = LitNodeClientConfig {
        lit_network: LitNetwork::DatilDev,
        alert_when_unauthorized: true,
        debug: true,
        connect_timeout: Duration::from_secs(30),
        check_node_attestation: false,
    };

    let mut client = LitNodeClient::new(config)
        .await
        .expect("Failed to create client");

    client.connect().await.expect("Failed to connect");

    // Create auth method
    let auth_method = EthWalletProvider::authenticate(&wallet, &client)
        .await
        .expect("Failed to create auth method");

    // Create resource ability requests
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    // Get session signatures
    let expiration = chrono::Utc::now() + chrono::Duration::minutes(10);
    let session_sigs = client
        .get_pkp_session_sigs(
            &pkp_public_key,
            &pkp_eth_address,
            vec![],
            vec![auth_method],
            resource_ability_requests,
            &expiration.to_rfc3339(),
        )
        .await
        .expect("Failed to get session signatures");

    // Execute the Lit Action
    let execute_params = ExecuteJsParams {
        code: Some(HELLO_WORLD_LIT_ACTION.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    let response = client.execute_js(execute_params)
        .await
        .expect("Failed to execute Lit Action");

    println!("Response: {:?}", response.response);
    println!("Logs: {}", response.logs);
}
```

## Core Concepts

### PKPs (Programmable Key Pairs)

PKPs are distributed ECDSA key pairs that can be programmed with signing logic. The private key never exists in any single location.

```rust
use lit_rust_sdk::blockchain::{resolve_address, Contract, PKPNFT};
use alloy::{network::EthereumWallet, primitives::U256, providers::ProviderBuilder};

// Mint a new PKP
let pkp_nft_address = resolve_address(Contract::PKPNFT, LitNetwork::Datil)
    .await
    .expect("Failed to resolve PKP NFT contract");

let pkp_nft = PKPNFT::new(pkp_nft_address, provider);

let mint_cost = pkp_nft.mintCost().call().await?;
let key_type = U256::from(2); // ECDSA key type

let tx = pkp_nft.mintNext(key_type).value(mint_cost);
let receipt = tx.send().await?.get_receipt().await?;
```

### Session Signatures

Session signatures provide temporary authentication for interacting with the Lit Network.

```rust
let session_sigs = client
    .get_pkp_session_sigs(
        &pkp_public_key,    // PKP public key in hex format
        &pkp_eth_address,   // PKP's Ethereum address
        capacity_auth_sigs, // Optional capacity delegation signatures
        auth_methods,       // Authentication methods (e.g., wallet signature)
        resource_ability_requests, // Permissions being requested
        &expiration,        // RFC3339 timestamp for expiration
    )
    .await?;
```

### Local Session Signatures (No PKP Required)

For simpler use cases where you don't need PKP signing capabilities, you can create session signatures directly with your wallet. This allows you to execute Lit Actions without minting or managing PKPs.

```rust
use lit_rust_sdk::{
    auth::load_wallet_from_env,
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig,
};

// Load your Ethereum wallet
let wallet = load_wallet_from_env().expect("Failed to load wallet");

// Create resource ability requests for Lit Action execution
let resource_ability_requests = vec![LitResourceAbilityRequest {
    resource: LitResourceAbilityRequestResource {
        resource: "*".to_string(),
        resource_prefix: "lit-litaction".to_string(),
    },
    ability: LitAbility::LitActionExecution.to_string(),
}];

// Set expiration for session signatures
let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

// Generate local session signatures using only your wallet
let session_sigs = client
    .get_local_session_sigs(
        &wallet,
        resource_ability_requests,
        &expiration,
    )
    .await?;

// Execute Lit Actions with these session signatures
let lit_action_code = r#"
const go = async () => {
  console.log("Hello from Lit Action!");
  Lit.Actions.setResponse({ response: "Executed without PKP!" });
};
go();
"#;

let execute_params = ExecuteJsParams {
    code: Some(lit_action_code.to_string()),
    ipfs_id: None,
    session_sigs,
    auth_methods: None,
    js_params: None,
};

let response = client.execute_js(execute_params).await?;
```

**Local Session Signatures:**

- **No PKP Required**: Execute Lit Actions using only your Ethereum wallet
- **Must have Ethereum wallet**: You must have an Ethereum wallet / local private key. Not suitable for cases where a PKP is the only wallet the user has.
- **Can still use PKP signing**: Can still sign with a PKP owned or controlled by the local wallet.

### Lit Actions

Lit Actions are JavaScript functions that execute on the Lit Network with access to PKP signing capabilities.

#### Signing Example

```rust
let signing_lit_action = r#"
const go = async () => {
  const utf8Encode = new TextEncoder();
  const toSign = utf8Encode.encode('Message to sign');
  const publicKey = "<PKP_PUBLIC_KEY>";
  const sigName = "sig1";

  const sigShare = await Lit.Actions.signEcdsa({
    toSign,
    publicKey,
    sigName
  });
};
go();
"#;

let execute_params = ExecuteJsParams {
    code: Some(signing_lit_action),
    ipfs_id: None,
    session_sigs,
    auth_methods: None,
    js_params: None,
};

let response = client.execute_js(execute_params).await?;
```

#### Passing Auth Methods to Lit Actions

You can pass additional auth methods that will be accessible via `Lit.Auth`:

```rust
// Create multiple auth methods
let auth_method1 = EthWalletProvider::authenticate(&wallet1, &client).await?;
let auth_method2 = EthWalletProvider::authenticate(&wallet2, &client).await?;

let execute_params = ExecuteJsParams {
    code: Some(lit_action_code),
    ipfs_id: None,
    session_sigs,
    auth_methods: Some(vec![auth_method1, auth_method2]),
    js_params: None,
};

// Inside the Lit Action, access auth methods via:
// Lit.Auth.authMethodContexts[0].userId
// Lit.Auth.authMethodContexts[0].authMethodType
```

### Capacity Delegation

Delegate network capacity to PKPs using Rate Limit NFTs:

```rust
use lit_rust_sdk::blockchain::RateLimitNFT;

// Mint a Rate Limit NFT
let rate_limit_nft = RateLimitNFT::new(rate_limit_address, provider);

let expires_at = U256::from(timestamp);
let cost = rate_limit_nft
    .calculateCost(requests_per_kilosecond, expires_at)
    .call()
    .await?;

let tx = rate_limit_nft.mint(expires_at).value(cost);
let receipt = tx.send().await?.get_receipt().await?;

// Create capacity delegation signature
let capacity_auth_sig = EthWalletProvider::create_capacity_delegation_auth_sig(
    &wallet,
    &rate_limit_nft_token_id,
    &[pkp_eth_address], // Delegate to PKP
    "10", // Number of uses
).await?;

// Use in session signature generation
let session_sigs = client.get_pkp_session_sigs(
    &pkp_public_key,
    &pkp_eth_address,
    vec![capacity_auth_sig], // Include capacity delegation
    vec![auth_method],
    resource_ability_requests,
    &expiration,
).await?;
```

## Environment Variables

The SDK expects the following environment variables for authentication:

```bash
# Required for wallet authentication
ETHEREUM_PRIVATE_KEY=your_private_key_here

# Required for PKP operations (if using existing PKP)
PKP_PUBLIC_KEY=0x...
PKP_TOKEN_ID=...
PKP_ETH_ADDRESS=0x...
```

## Network Configuration

The SDK supports multiple Lit Networks:

- `LitNetwork::Datil` - Production network
- `LitNetwork::DatilDev` - Development network (recommended for testing)
- `LitNetwork::DatilTest` - Test network

Each network has different characteristics:

- **Datil**: Production environment with real assets
- **DatilDev**: Development environment with test assets, faster iteration
- **DatilTest**: Test environment for integration testing

## Testing

Run the test suite:

```bash
# Run all tests
cargo test -- --nocapture

# Run specific test
cargo test test_execute_js_hello_world -- --nocapture

# Run with debug output
RUST_LOG=debug cargo test -- --nocapture
```

## API Reference

### LitNodeClient

The main client for interacting with the Lit Network.

#### Methods

- `new(config: LitNodeClientConfig) -> Result<Self>` - Create a new client
- `connect() -> Result<()>` - Connect to the Lit Network
- `is_ready() -> bool` - Check if client is connected and ready
- `connected_nodes() -> Vec<String>` - Get list of connected node URLs
- `get_connection_state() -> ConnectionState` - Get detailed connection state
- `execute_js(params: ExecuteJsParams) -> Result<ExecuteJsResponse>` - Execute a Lit Action
- `get_pkp_session_sigs(...) -> Result<SessionSignatures>` - Generate session signatures with PKP
- `get_local_session_sigs(wallet: &PrivateKeySigner, resource_ability_requests: Vec<LitResourceAbilityRequest>, expiration: &str) -> Result<SessionSignatures>` - Generate session signatures without PKP

### Authentication

#### EthWalletProvider

Provides Ethereum wallet-based authentication.

- `authenticate(wallet: &PrivateKeySigner, client: &LitNodeClient) -> Result<AuthMethod>`
- `create_capacity_delegation_auth_sig(...) -> Result<AuthSig>`
- `load_wallet_from_env() -> Result<PrivateKeySigner>`

### Types

#### ExecuteJsParams

```rust
pub struct ExecuteJsParams {
    pub code: Option<String>,           // JavaScript code to execute
    pub ipfs_id: Option<String>,        // IPFS CID of code
    pub session_sigs: SessionSignatures, // Session signatures for auth
    pub auth_methods: Option<Vec<AuthMethod>>, // Additional auth methods
    pub js_params: Option<serde_json::Value>, // Parameters to pass to JS
}
```

#### ExecuteJsResponse

```rust
pub struct ExecuteJsResponse {
    pub response: serde_json::Value,    // Response from Lit Action
    pub logs: String,                   // Console logs from execution
    pub signatures: Option<HashMap<String, String>>, // Generated signatures
}
```

## Examples

### Complete Workflow: Mint PKP and Execute Action

See `tests/execute_js_test.rs::test_execute_js_with_capacity_delegation_datil` for a complete example that:

1. Mints a new PKP NFT
2. Mints a Rate Limit NFT for capacity
3. Creates capacity delegation
4. Generates session signatures
5. Executes a Lit Action

### Local Session Signatures (No PKP)

See `tests/local_session_sigs_test.rs` for examples of executing Lit Actions without PKPs:

- `test_local_session_sigs_hello_world` - Basic Lit Action execution with local session signatures
- `test_local_session_sigs_with_params` - Advanced Lit Action with computations and parameters

### Authentication Methods

See `tests/execute_js_test.rs::test_execute_js_with_auth_methods` for an example of passing multiple authentication methods to a Lit Action.

## Troubleshooting

### Connection Issues

If you're having trouble connecting to the network:

1. Ensure you're using the correct network (DatilDev is recommended for testing)
2. Check your internet connection
3. Verify firewall settings allow HTTPS connections
4. Enable debug mode in the client configuration

### Authentication Failures

If authentication is failing:

1. Verify your `ETHEREUM_PRIVATE_KEY` is correctly set
2. Ensure the wallet has sufficient balance for gas fees
3. Check that PKP credentials match (public key, token ID, ETH address)

### Lit Action Execution Errors

Common issues and solutions:

- **"Unauthorized"**: Check session signatures haven't expired
- **"Invalid signature"**: Verify PKP public key format (should include 0x prefix)
- **"Rate limit exceeded"**: Ensure Rate Limit NFT has sufficient capacity

## CI/Development

The repository includes comprehensive GitHub Actions workflows for testing and validation:

### CI Pipeline

- **Basic CI** (`ci.yml`): Runs on every push/PR with formatting, clippy, unit tests, and all integration tests
- **Documentation** (`docs.yml`): Validates README files and builds documentation
- **Release Tests** (`release.yml`): Full test suite that can be run manually for release testing

### Required GitHub Secrets

For CI to work properly, the following secrets must be configured in the repository:

```bash
ETHEREUM_PRIVATE_KEY    # Private key for test wallet (should have test ETH)
PKP_PUBLIC_KEY         # Existing PKP public key for tests (optional)
PKP_TOKEN_ID           # Existing PKP token ID for tests (optional)
PKP_ETH_ADDRESS        # Existing PKP Ethereum address for tests (optional)
ETHEREUM_RPC_URL       # RPC URL for Ethereum/L2 network interactions
```

**Note**: The CI will work with just `ETHEREUM_PRIVATE_KEY` and `ETHEREUM_RPC_URL` for basic tests. PKP-related secrets are only needed for advanced tests.

## Contributing

Contributions are welcome! Please ensure all tests pass before submitting a PR:

```bash
cargo test -- --nocapture
cargo fmt
cargo clippy
```

### Running Tests Locally

```bash
# Run all tests (requires environment variables)
cargo test -- --nocapture

# Run only local session signature tests (simpler setup)
cargo test local_session_sigs -- --nocapture

# Run specific test
cargo test test_connect_to_lit_network -- --nocapture
```

## License

See LICENSE file in the repository root.

## Resources

- [Lit Protocol Documentation](https://developer.litprotocol.com/)
- [JavaScript SDK API Reference](https://v7-api-doc-lit-js-sdk.vercel.app/)
- [GitHub Repository](https://github.com/LIT-Protocol/rust-sdk)

## Support

For issues and questions:

- Open an issue on GitHub
- Visit the [Lit Protocol Discord](https://discord.gg/lit-protocol)
- Check the [official documentation](https://developer.litprotocol.com/)
