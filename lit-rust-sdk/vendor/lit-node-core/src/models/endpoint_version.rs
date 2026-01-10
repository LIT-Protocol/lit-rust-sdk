use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointVersion {
    #[default]
    Initial,
    V1,
    V2,
}

impl EndpointVersion {
    pub const fn as_str(&self) -> &str {
        match self {
            EndpointVersion::Initial => "",
            EndpointVersion::V1 | EndpointVersion::V2 => "/v2",
        }
    }
}
