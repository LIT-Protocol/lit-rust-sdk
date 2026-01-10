use crate::{JsonAuthSig, MultipleAuthSigs};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AuthSigItem {
    Single(JsonAuthSig),
    Multiple(MultipleAuthSigs),
}

impl Default for AuthSigItem {
    fn default() -> Self {
        Self::Single(Default::default())
    }
}
