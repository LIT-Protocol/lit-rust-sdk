use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("Not enough nodes connected: got {connected}, need {required}")]
    NotEnoughNodes { connected: usize, required: usize },

    #[error("Handshake failed for node {url}: {reason}")]
    HandshakeFailed { url: String, reason: String },

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("Contract error: {0}")]
    Contract(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Bls error: {0}")]
    BlsError(#[from] blsful::BlsError),

    #[error("Bare serialization error: {0}")]
    BareError(#[from] serde_bare::error::Error),

    #[error("Staking contract error: {0}")]
    ContractError(
        #[from]
        ethers::contract::ContractError<ethers::providers::Provider<ethers::providers::Http>>,
    ),
}

pub type Result<T> = std::result::Result<T, Error>;
