//! Admin endpoint methods and data

mod get_blinders;
mod get_key_backup;
mod set_blinders;

pub use get_blinders::*;
pub use get_key_backup::*;
pub use set_blinders::*;

use serde::{Deserialize, Serialize};

/// The response from an admin endpoint that doesn't return a result
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdminPlainResponse {
    /// The value of the response
    pub success: bool,
}
