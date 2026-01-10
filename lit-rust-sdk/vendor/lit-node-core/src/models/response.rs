use super::{DynamicPaymentItem, SignableOutput, SignedData, default_epoch};
use lit_rust_crypto::blsful::{Bls12381G2Impl, SignatureShare};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSDKHandshakeResponse {
    pub server_public_key: String,
    pub subnet_public_key: String,
    pub network_public_key: String,
    pub network_public_key_set: String,
    pub client_sdk_version: String,
    pub hd_root_pubkeys: Vec<String>,
    pub attestation: Option<Value>,
    pub latest_blockhash: String,
    pub node_version: String,
    pub node_identity_key: String,
    #[serde(default = "default_epoch")]
    pub epoch: u64,
    pub git_commit_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionSignResponse {
    pub result: String,
    pub signature_share: SignatureShare<Bls12381G2Impl>,
    pub share_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct GenericResponse<T>
where
    T: Serialize + DeserializeOwned,
{
    pub ok: bool,
    pub error: Option<String>,
    #[serde(rename = "errorObject")]
    pub error_object: Option<String>,
    pub data: Option<T>,
}

impl<T> GenericResponse<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            error: None,
            error_object: None,
            data: Some(data),
        }
    }
}

impl GenericResponse<String> {
    pub fn err(error: String) -> Self {
        Self {
            ok: false,
            error: Some(error),
            error_object: None,
            data: None,
        }
    }
    pub fn err_and_data(error: String, object: String) -> Self {
        Self {
            ok: false,
            error: Some(error),
            error_object: Some(object),
            data: None,
        }
    }

    pub fn err_and_data_json<E: Serialize + DeserializeOwned>(error: String, object: E) -> Self {
        Self::err_and_data(
            error,
            serde_json::to_string(&object).expect("to serialize to string"),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSignSessionKeyResponseV2 {
    pub result: String,
    pub signature_share: SignatureShare<Bls12381G2Impl>,
    pub share_id: String,
    pub curve_type: String,
    pub siwe_message: String,
    pub data_signed: String,
    pub bls_root_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonPKPSigningResponse {
    pub success: bool,
    pub signed_data: Vec<u8>,
    pub signature_share: SignableOutput,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutionResponse {
    pub success: bool,
    pub signed_data: HashMap<String, SignedData>,
    pub decrypted_data: Value,
    pub claim_data: HashMap<String, JsonPKPClaimKeyResponse>,
    pub response: String,
    pub logs: String,
    pub payment_detail: Option<Vec<DynamicPaymentItem>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPKPClaimKeyResponse {
    pub signature: String,
    pub derived_key_id: String,
}
