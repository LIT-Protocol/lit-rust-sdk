use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type AccessControlConditionItem = ControlConditionItem<JsonAccessControlCondition>;
pub type SolRpcConditionItem = ControlConditionItem<SolRpcConditionV2Options>;
pub type UnifiedAccessControlConditionItem = ControlConditionItem<UnifiedAccessControlCondition>;
pub type EVMContractConditionItem = ControlConditionItem<EVMContractCondition>;
pub type CosmosConditionItem = ControlConditionItem<CosmosCondition>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum ControlConditionItem<T> {
    Condition(T),
    Operator(JsonAccessControlConditionOperator),
    Group(Vec<ControlConditionItem<T>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
#[allow(clippy::enum_variant_names)]
pub enum UnifiedAccessControlCondition {
    JsonAccessControlCondition(JsonAccessControlCondition),
    SolRpcCondition(SolRpcConditionV2Options),
    EVMContractCondition(EVMContractCondition),
    CosmosCondition(CosmosCondition),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolRpcConditionV2Options {
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub pda_params: Option<Vec<String>>,
    pub pda_interface: Option<SolPdaInterface>,
    pub pda_key: Option<String>,
    pub chain: String,
    pub return_value_test: JsonReturnValueTestV2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolRpcConditionV2 {
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub pda_params: Vec<String>,
    pub pda_interface: SolPdaInterface,
    pub pda_key: String,
    pub chain: String,
    pub return_value_test: JsonReturnValueTestV2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolRpcCondition {
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub chain: String,
    pub return_value_test: JsonReturnValueTestV2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolPdaInterface {
    pub offset: usize,
    pub fields: HashMap<String, usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum SolRpcConditionItemV0 {
    Condition(SolRpcCondition),
    Operator(JsonAccessControlConditionOperator),
    Group(Vec<SolRpcConditionItem>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EVMContractCondition {
    pub contract_address: String,
    pub function_name: String,
    pub function_params: Vec<String>,
    pub function_abi: ethabi::Function,
    pub chain: String,
    pub return_value_test: JsonReturnValueTestV2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonAccessControlCondition {
    pub contract_address: String,
    pub chain: String,
    pub standard_contract_type: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub return_value_test: JsonReturnValueTest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonAccessControlConditionOperator {
    pub operator: AccessControlBooleanOperator,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccessControlBooleanOperator {
    And,
    Or,
}

impl std::fmt::Display for AccessControlBooleanOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AccessControlBooleanOperator::And => write!(f, "AND"),
            AccessControlBooleanOperator::Or => write!(f, "OR"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosCondition {
    pub path: String,
    pub chain: String,
    pub method: Option<String>,
    pub parameters: Option<Vec<String>>,
    pub return_value_test: JsonReturnValueTestV2,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlock {
    #[serde(rename = "block_id")]
    pub block_id: CosmosBlockId,
    pub block: CosmosBlockBlock,
    #[serde(rename = "sdk_block")]
    pub sdk_block: CosmosBlockSdkBlock,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockId {
    pub hash: String,
    #[serde(rename = "part_set_header")]
    pub part_set_header: CosmosPartSetHeader,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosPartSetHeader {
    pub total: i64,
    pub hash: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockData {
    pub txs: Vec<serde_json::Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockEvidence {
    pub evidence: Vec<serde_json::Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockLastCommit {
    pub height: String,
    pub round: i64,
    #[serde(rename = "block_id")]
    pub block_id: CosmosBlockId,
    pub signatures: Vec<CosmosBlockSignature>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockSignature {
    #[serde(rename = "block_id_flag")]
    pub block_id_flag: String,
    #[serde(rename = "validator_address")]
    pub validator_address: Option<String>,
    pub timestamp: String,
    pub signature: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockSdkBlock {
    pub header: CosmosBlockHeader,
    pub data: CosmosBlockData,
    pub evidence: CosmosBlockEvidence,
    #[serde(rename = "last_commit")]
    pub last_commit: CosmosBlockLastCommit,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockBlock {
    pub header: CosmosBlockHeader,
    pub data: CosmosBlockData,
    pub evidence: CosmosBlockEvidence,
    #[serde(rename = "last_commit")]
    pub last_commit: CosmosBlockLastCommit,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosmosBlockHeader {
    pub version: Version,
    #[serde(rename = "chain_id")]
    pub chain_id: String,
    pub height: String,
    pub time: String,
    #[serde(rename = "last_block_id")]
    pub last_block_id: CosmosBlockId,
    #[serde(rename = "last_commit_hash")]
    pub last_commit_hash: String,
    #[serde(rename = "data_hash")]
    pub data_hash: String,
    #[serde(rename = "validators_hash")]
    pub validators_hash: String,
    #[serde(rename = "next_validators_hash")]
    pub next_validators_hash: String,
    #[serde(rename = "consensus_hash")]
    pub consensus_hash: String,
    #[serde(rename = "app_hash")]
    pub app_hash: String,
    #[serde(rename = "last_results_hash")]
    pub last_results_hash: String,
    #[serde(rename = "evidence_hash")]
    pub evidence_hash: String,
    #[serde(rename = "proposer_address")]
    pub proposer_address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonReturnValueTest {
    pub comparator: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonReturnValueTestV2 {
    pub key: String,
    pub comparator: String,
    pub value: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub block: String,
    pub app: String,
}
