use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedData {
    pub sig_type: String,
    pub signature_share: String,
    pub public_key: String,
    pub sig_name: String,
}
