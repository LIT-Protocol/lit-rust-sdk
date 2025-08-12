use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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