use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSet {
    pub socket_address: String,
    pub value: u64,
}
