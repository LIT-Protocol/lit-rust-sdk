use reqwest::header::ToStrError;
use thiserror::Error;

/// Errors produced by this crate
#[derive(Debug, Error)]
pub enum SdkError {
    /// Errors from IO
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Errors from inner crate `reqwest`
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Error when converting an HTTP response header to a string
    #[error("Http header to string error: {0}")]
    HeaderToStr(#[from] ToStrError),
    /// Errors from inner crate `serde_json`
    #[error("Serde error: {0}")]
    Json(#[from] serde_json::Error),
    /// Errors from the hex crate
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Signature errors from the ecdsa crate
    #[error("Signature error: {0}")]
    EcdsaSignature(#[from] ecdsa::signature::Error),
    /// Bls errors from the blsful crate
    #[error("Bls error: {0}")]
    Bls(#[from] lit_node_core::lit_rust_crypto::blsful::BlsError),
    /// Errors from string parsing
    #[error("String parse error: {0}")]
    Parse(String),
    /// Errors from calling the build methods on Request builders
    #[error("Build request error: {0}")]
    Build(String),
    /// Errors from decrypting a payload
    #[error("Decryption error: {0}")]
    Decryption(String),
    /// Errors from attestation verification
    #[error("The Attestation report data doesn't match the provided data")]
    Attestation,
    /// Errors when converting between types
    #[error("Invalid type conversion: {0}")]
    InvalidType(String),
    /// Signature combination errors
    #[error("An error occurred while combining signatures: {0}")]
    SignatureCombine(String),
    /// Signature verification error
    #[error("Signature does not verify with the given message and public key")]
    SignatureVerify,
    /// Errors from admin endpoints
    #[error("Admin endpoint error: {0}")]
    Admin(String),
}

/// Results produced by this crate
pub type SdkResult<T> = Result<T, SdkError>;

impl From<lit_node_core::Error> for SdkError {
    fn from(e: lit_node_core::Error) -> Self {
        match e {
            lit_node_core::Error::Parse(e) => SdkError::Parse(e),
            lit_node_core::Error::InvalidType(e) => SdkError::InvalidType(e),
        }
    }
}
