use super::default_epoch;
use crate::{
    AccessControlConditionItem, AuthMethod, AuthSigItem, CurveType, EVMContractConditionItem,
    Invocation, NodeSet, SigningScheme, SolRpcConditionItem, UnifiedAccessControlConditionItem,
};
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSDKHandshakeRequest {
    pub client_public_key: String,
    pub challenge: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionSignRequest {
    pub access_control_conditions: Option<Vec<AccessControlConditionItem>>,
    pub evm_contract_conditions: Option<Vec<EVMContractConditionItem>>,
    pub sol_rpc_conditions: Option<Vec<SolRpcConditionItem>>,
    pub unified_access_control_conditions: Option<Vec<UnifiedAccessControlConditionItem>>,
    pub chain: Option<String>,
    pub data_to_encrypt_hash: String,
    pub auth_sig: AuthSigItem,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSignSessionKeyRequestV2 {
    pub session_key: String,
    pub auth_methods: Vec<AuthMethod>,
    pub pkp_public_key: Option<String>,
    pub auth_sig: Option<AuthSigItem>, // For backwards compatibility
    pub siwe_message: String,
    pub curve_type: CurveType,
    pub code: Option<String>,
    pub lit_action_ipfs_id: Option<String>,
    pub js_params: Option<Value>,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
    pub node_set: Vec<NodeSet>,
    pub max_price: U256,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPKPSigningRequest {
    pub to_sign: Vec<u8>,
    pub pubkey: String,
    pub auth_sig: AuthSigItem,
    pub auth_methods: Option<Vec<AuthMethod>>, // For backwards compatibility
    pub signing_scheme: SigningScheme,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
    pub node_set: Vec<NodeSet>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutionRequest {
    pub code: Option<String>,
    pub ipfs_id: Option<String>,
    pub auth_sig: AuthSigItem,
    pub js_params: Option<Value>,
    pub auth_methods: Option<Vec<AuthMethod>>,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
    pub node_set: Vec<NodeSet>,
    #[serde(default)]
    pub invocation: Invocation,
}

impl JsonExecutionRequest {
    pub fn is_async(&self) -> bool {
        self.invocation == Invocation::Async
    }
}

impl std::fmt::Debug for JsonExecutionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MAX_CODE_LEN: usize = 500;

        let truncated_code = self.code.as_ref().map(|code| {
            if code.len() > MAX_CODE_LEN {
                format!(
                    "{}... (truncated, {} bytes total)",
                    &code[..MAX_CODE_LEN],
                    code.len()
                )
            } else {
                code.to_string()
            }
        });

        f.debug_struct("JsonExecutionRequest")
            .field("code", &truncated_code)
            .field("ipfs_id", &self.ipfs_id)
            .field("auth_sig", &self.auth_sig)
            .field("js_params", &self.js_params)
            .field("auth_methods", &self.auth_methods)
            .field("epoch", &self.epoch)
            .field("node_set", &self.node_set)
            .field("invocation", &self.invocation)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonPKPClaimKeyRequest {
    pub auth_method: AuthMethod,
    pub credential_public_key: Option<String>,
}
