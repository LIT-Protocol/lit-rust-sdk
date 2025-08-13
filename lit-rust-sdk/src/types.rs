use blsful::{Bls12381G2Impl, SignatureShare as BlsfulSignatureShare};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    #[serde(rename = "clientPublicKey")]
    pub client_public_key: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    #[serde(rename = "serverPublicKey")]
    pub server_pub_key: String,
    #[serde(rename = "subnetPublicKey")]
    pub subnet_pub_key: String,
    #[serde(rename = "networkPublicKey")]
    pub network_pub_key: String,
    #[serde(rename = "networkPublicKeySet")]
    pub network_pub_key_set: String,
    #[serde(rename = "hdRootPubkeys")]
    pub hd_root_pubkeys: Vec<String>,
    #[serde(rename = "latestBlockhash")]
    pub latest_blockhash: String,
    #[serde(rename = "clientSdkVersion", skip_serializing_if = "Option::is_none")]
    pub client_sdk_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct NodeConnectionInfo {
    pub url: String,
    pub handshake_response: HandshakeResponse,
}

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub connected_nodes: Vec<String>,
    pub server_keys: HashMap<String, HandshakeResponse>,
    pub subnet_pub_key: Option<String>,
    pub network_pub_key: Option<String>,
    pub network_pub_key_set: Option<String>,
    pub hd_root_pubkeys: Option<Vec<String>>,
    pub latest_blockhash: Option<String>,
}

// PKP related types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKP {
    #[serde(rename = "tokenId")]
    pub token_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "ethAddress")]
    pub eth_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSig {
    pub sig: String,
    #[serde(rename = "derivedVia")]
    pub derived_via: String,
    #[serde(rename = "signedMessage")]
    pub signed_message: String,
    pub address: String,
    pub algo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    #[serde(rename = "authMethodType")]
    pub auth_method_type: u32,
    #[serde(rename = "accessToken")]
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LitResourceAbilityRequest {
    pub resource: LitResourceAbilityRequestResource,
    pub ability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LitResourceAbilityRequestResource {
    /// The resource ID
    pub resource: String,
    /// The resource prefix
    pub resource_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LitAbility {
    // Used by top level auth sigs
    AccessControlConditionDecryption,
    AccessControlConditionSigning,
    PKPSigning,
    RateLimitIncreaseAuth,
    LitActionExecution,
}

impl fmt::Display for LitAbility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LitAbility::AccessControlConditionDecryption => {
                write!(f, "access-control-condition-decryption")
            }
            LitAbility::AccessControlConditionSigning => {
                write!(f, "access-control-condition-signing")
            }
            LitAbility::PKPSigning => write!(f, "pkp-signing"),
            LitAbility::RateLimitIncreaseAuth => write!(f, "rate-limit-increase-auth"),
            LitAbility::LitActionExecution => write!(f, "lit-action-execution"),
        }
    }
}

// USER DEFINED
const LIT_RESOURCE_PREFIX_ACC: &str = "lit-accesscontrolcondition";
const LIT_RESOURCE_PREFIX_PKP: &str = "lit-pkp";
const LIT_RESOURCE_PREFIX_RLI: &str = "lit-ratelimitincrease";
const LIT_RESOURCE_PREFIX_LA: &str = "lit-litaction";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    pub sig: String,
    #[serde(rename = "derivedVia")]
    pub derived_via: String,
    #[serde(rename = "signedMessage")]
    pub signed_message: String,
    pub address: String,
    pub algo: Option<String>,
}

pub type SessionSignatures = HashMap<String, SessionSignature>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignSessionKeyRequest {
    #[serde(rename = "sessionKey")]
    pub session_key: String,
    #[serde(rename = "authMethods")]
    pub auth_methods: Vec<AuthMethod>,
    #[serde(rename = "pkpPublicKey")]
    pub pkp_public_key: String,
    #[serde(rename = "siweMessage")]
    pub siwe_message: String,
    #[serde(rename = "curveType")]
    pub curve_type: String,
    #[serde(rename = "epoch", skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityDelegationRequest {
    #[serde(rename = "capacityTokenId")]
    pub capacity_token_id: String,
    #[serde(rename = "delegateeAddresses")]
    pub delegatee_addresses: Vec<String>,
    pub uses: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKeySignedMessage {
    pub session_key: String,
    pub resource_ability_requests: Vec<LitResourceAbilityRequest>,
    pub capabilities: Vec<AuthSig>,
    pub issued_at: String,
    pub expiration: String,
    pub node_address: String,
}

// Execute JS types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteJsParams {
    pub code: Option<String>,
    #[serde(rename = "ipfsId")]
    pub ipfs_id: Option<String>,
    #[serde(rename = "sessionSigs")]
    pub session_sigs: SessionSignatures,
    #[serde(rename = "authMethods")]
    pub auth_methods: Option<Vec<AuthMethod>>,
    #[serde(rename = "jsParams")]
    pub js_params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteJsResponse {
    pub claims: HashMap<String, serde_json::Value>,
    pub signatures: Option<serde_json::Value>,
    pub decryptions: Vec<serde_json::Value>,
    pub response: serde_json::Value,
    pub logs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeShare {
    pub success: bool,
    #[serde(rename = "signedData")]
    pub signed_data: HashMap<String, serde_json::Value>,
    #[serde(rename = "claimData")]
    pub claim_data: HashMap<String, serde_json::Value>,
    pub response: serde_json::Value,
    pub logs: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonSignSessionKeyResponseV1 {
    pub result: String,
    pub signature_share: BlsfulSignatureShare<Bls12381G2Impl>,
    pub share_index: u32,
    pub curve_type: String,
    pub siwe_message: String,
    pub data_signed: String,
    pub bls_root_pubkey: String,
}
