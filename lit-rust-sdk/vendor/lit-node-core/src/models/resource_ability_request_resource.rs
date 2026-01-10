use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LitResourceAbilityRequestResource {
    /// The resource ID
    pub resource: String,
    /// The resource prefix
    pub resource_prefix: String,
}
