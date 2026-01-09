use serde::{Deserialize, Serialize};

#[cfg(not(test))]
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Serialize, Deserialize, Clone, Default)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    pub auth_method_type: u32,
    pub access_token: String,
}

#[cfg(not(test))]
impl Debug for AuthMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMethod")
            .field("auth_method_type", &self.auth_method_type)
            .field("access_token", &"****filtered****")
            .finish()
    }
}

#[cfg(not(test))]
impl Display for AuthMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthMethod {{ auth_method_type: {}, access_token: ****filtered**** }}",
            self.auth_method_type
        )
    }
}
