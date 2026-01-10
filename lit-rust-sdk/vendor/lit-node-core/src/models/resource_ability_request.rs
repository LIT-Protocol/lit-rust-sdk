use super::LitResourceAbilityRequestResource;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LitResourceAbilityRequest {
    pub resource: LitResourceAbilityRequestResource,
    pub ability: String,
}
