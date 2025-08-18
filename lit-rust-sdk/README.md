# Lit Protocol Rust SDK

A native Rust implementation of the Lit Protocol SDK, providing programmatic access to the Lit Network for distributed key management, conditional access control, and programmable signing.

Currently in Beta and only supports Datil, DatilDev, and DatilTest networks.

## Features

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
lit-rust-sdk = "0.1.0"
tokio = { version = "1.40", features = ["full"] }
```

## Quick Start

```rust
use lit_rust_sdk::{LitNetwork, LitNodeClient, LitNodeClientConfig};
use std::time::Duration;

#[tokio::main]
async fn main() {
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

    println!("Connected to {} nodes", client.connected_nodes().len());
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
