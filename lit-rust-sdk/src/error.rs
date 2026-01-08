use thiserror::Error;

#[derive(Debug, Error)]
pub enum LitSdkError {
    #[error("network error: {0}")]
    Network(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("invalid config: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("access control conditions error: {0}")]
    Accs(String),

    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl From<reqwest::Error> for LitSdkError {
    fn from(e: reqwest::Error) -> Self {
        LitSdkError::Network(e.to_string())
    }
}

impl From<lit_sdk::SdkError> for LitSdkError {
    fn from(e: lit_sdk::SdkError) -> Self {
        LitSdkError::Crypto(e.to_string())
    }
}
