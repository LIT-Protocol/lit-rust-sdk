# Lit Protocol Rust SDK

A native Rust implementation of the Lit Protocol SDK, providing programmatic access to the Lit Network for distributed key management, conditional access control, and programmable signing.

Currently in Beta and only supports Datil, DatilDev, and DatilTest networks.

## Features

- **Local Session Signatures**: Execute Lit Actions using only your Ethereum wallet (no PKP required)
- **PKP Management**: Mint and manage Programmable Key Pairs (PKPs)
- **Session Signatures**: Generate and manage session signatures for authentication
- **Lit Actions**: Execute JavaScript code on the Lit Network with access to PKP signing capabilities
- **Encryption & Decryption**: BLS encryption with access control conditions and client-side decryption
- **Capacity Delegation**: Delegate network capacity using Rate Limit NFTs
- **Multi-Network Support**: Connect to Datil, DatilDev, and DatilTest networks
- **Ethereum Wallet Integration**: Native support for Ethereum wallet authentication

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
lit-rust-sdk = "0.1.0"
tokio = { version = "1.40", features = ["full"] }
```

## Quick Start

Execute a Lit Action using only your Ethereum wallet (no PKP required):

```rust
use lit_rust_sdk::{
    auth::load_wallet_from_env,
    types::{LitAbility, LitResourceAbilityRequest, LitResourceAbilityRequestResource},
    ExecuteJsParams, LitNetwork, LitNodeClient, LitNodeClientConfig,
};
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Load wallet from environment variable
    let wallet = load_wallet_from_env()
        .expect("Set ETHEREUM_PRIVATE_KEY environment variable");

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

    // Create session signatures without PKP
    let resource_ability_requests = vec![LitResourceAbilityRequest {
        resource: LitResourceAbilityRequestResource {
            resource: "*".to_string(),
            resource_prefix: "lit-litaction".to_string(),
        },
        ability: LitAbility::LitActionExecution.to_string(),
    }];

    let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
    let session_sigs = client
        .get_local_session_sigs(&wallet, resource_ability_requests, &expiration)
        .await
        .expect("Failed to create session signatures");

    // Execute Lit Action
    let execute_params = ExecuteJsParams {
        code: Some(r#"
            const go = async () => {
                console.log("Hello from Lit Action!");
                Lit.Actions.setResponse({ response: "Hello World!" });
            };
            go();
        "#.to_string()),
        ipfs_id: None,
        session_sigs,
        auth_methods: None,
        js_params: None,
    };

    let response = client.execute_js(execute_params).await
        .expect("Failed to execute Lit Action");

    println!("Response: {:?}", response.response);
}
```

## Documentation

For comprehensive documentation, examples, and guides, please visit:

- [Full Documentation and Examples](https://github.com/LIT-Protocol/lit-rust-sdk#readme)
- [API Reference](https://docs.rs/lit-rust-sdk)
- [Lit Protocol Documentation](https://developer.litprotocol.com/)
- [JavaScript SDK Reference](https://v7-api-doc-lit-js-sdk.vercel.app/)

## License

See LICENSE file in the repository root.
