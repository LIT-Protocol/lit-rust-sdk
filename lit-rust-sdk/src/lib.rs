//! # Lit Protocol Rust SDK
//!
//! A native Rust implementation of the Lit Protocol SDK, providing programmatic access
//! to the Lit Network for distributed key management, conditional access control,
//! and programmable signing.
//!
//! ## Quick Start
//!
//! ```no_run
//! use lit_rust_sdk::{LitNetwork, LitNodeClient, LitNodeClientConfig};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure the client
//!     let config = LitNodeClientConfig {
//!         lit_network: LitNetwork::DatilDev,
//!         alert_when_unauthorized: true,
//!         debug: true,
//!         connect_timeout: Duration::from_secs(30),
//!         check_node_attestation: false,
//!     };
//!
//!     // Create and connect to the Lit Network
//!     let mut client = LitNodeClient::new(config).await?;
//!     client.connect().await?;
//!     
//!     println!("Connected to {} nodes", client.connected_nodes().len());
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - **PKP Management**: Mint and manage Programmable Key Pairs (PKPs)
//! - **Session Signatures**: Generate and manage session signatures for authentication
//! - **Lit Actions**: Execute JavaScript code on the Lit Network
//! - **Capacity Delegation**: Delegate network capacity using Rate Limit NFTs
//! - **Multi-Network Support**: Connect to Datil, DatilDev, and DatilTest networks
//!
//! ## Main Components
//!
//! - [`LitNodeClient`]: Main client for interacting with the Lit Network
//! - [`LitNodeClientConfig`]: Configuration for the client
//! - [`ExecuteJsParams`]: Parameters for executing Lit Actions
//! - [`auth::EthWalletProvider`]: Ethereum wallet authentication provider
//!
//! For comprehensive documentation and examples, see the
//! [GitHub repository](https://github.com/LIT-Protocol/rust-sdk).

pub mod auth;
pub mod blockchain;
pub mod bls;
pub mod client;
pub mod config;
pub mod types;

pub use client::LitNodeClient;
pub use config::{LitNetwork, LitNodeClientConfig};
pub use types::{
    AccessControlCondition, AuthMethod, AuthSig, EncryptRequest, EncryptResponse,
    EvmContractCondition, ExecuteJsParams, ExecuteJsResponse, ReturnValueTest,
    SessionSignatures, SolRpcCondition, UnifiedAccessControlCondition, PKP,
};
