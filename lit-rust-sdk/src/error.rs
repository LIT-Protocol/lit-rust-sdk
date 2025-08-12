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
}

pub type Result<T> = std::result::Result<T, Error>;