use thiserror::Error;

/// Errors that occur in this crate
#[derive(Debug, Error)]
pub enum Error {
    #[error("Parse error {0}")]
    Parse(String),
    #[error("Invalid type error {0}")]
    InvalidType(String),
}

/// Results returned in this crate
pub type Result<T> = std::result::Result<T, Error>;

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::Parse(e.to_string())
    }
}
