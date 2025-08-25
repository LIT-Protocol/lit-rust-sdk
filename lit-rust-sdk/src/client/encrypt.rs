use crate::client::LitNodeClient;
use crate::types::{EncryptRequest, EncryptResponse};
use alloy::providers::Provider as ProviderTrait;
use eyre::{eyre, Result};
use sha2::{Digest, Sha256};
use tracing::debug;

impl<P> LitNodeClient<P>
where
    P: ProviderTrait,
{
    /// Encrypt data using BLS encryption with access control conditions
    ///
    /// # Arguments
    ///
    /// * `params` - The encryption request containing the data and access control conditions
    ///
    /// # Returns
    ///
    /// * `Result<EncryptResponse>` - The encrypted ciphertext and hash of the data
    pub async fn encrypt(&self, params: EncryptRequest) -> Result<EncryptResponse> {
        // Validate that client is ready
        if !self.ready {
            return Err(eyre!(
                "LitNodeClient is not ready. Please call await client.connect() first."
            ));
        }

        // Validate that subnet_pub_key exists
        let subnet_pub_key = self
            .subnet_pub_key
            .as_ref()
            .ok_or_else(|| eyre!("subnet_pub_key cannot be null"))?;

        // Validate that at least one type of access control condition is provided
        let has_conditions = params.access_control_conditions.is_some()
            || params.evm_contract_conditions.is_some()
            || params.sol_rpc_conditions.is_some()
            || params.unified_access_control_conditions.is_some();

        if !has_conditions {
            return Err(eyre!(
                "You must provide either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions"
            ));
        }

        // Hash the access control conditions
        let hash_of_conditions = self.get_hashed_access_control_conditions(&params)?;
        let hash_of_conditions_str = hex::encode(&hash_of_conditions);

        debug!("hashOfConditionsStr: {}", hash_of_conditions_str);

        // Hash the private data
        let mut hasher = Sha256::new();
        hasher.update(&params.data_to_encrypt);
        let hash_of_private_data = hasher.finalize();
        let hash_of_private_data_str = hex::encode(&hash_of_private_data);

        debug!("hashOfPrivateDataStr: {}", hash_of_private_data_str);

        // Assemble identity parameter
        let identity_param = self
            .get_identity_param_for_encryption(&hash_of_conditions_str, &hash_of_private_data_str);

        debug!("identityParam: {}", identity_param);

        // Remove 0x prefix from subnet_pub_key if present
        let clean_pub_key = subnet_pub_key.strip_prefix("0x").unwrap_or(subnet_pub_key);

        // Encrypt using BLS
        let ciphertext_bytes = crate::bls::encrypt(
            &hex::decode(clean_pub_key)?,
            &params.data_to_encrypt,
            identity_param.as_bytes(),
        )?;

        // Convert to base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let ciphertext = STANDARD.encode(&ciphertext_bytes);

        Ok(EncryptResponse {
            ciphertext,
            data_to_encrypt_hash: hash_of_private_data_str,
        })
    }

    /// Hash the access control conditions to match lit-node implementation
    fn get_hashed_access_control_conditions(&self, params: &EncryptRequest) -> Result<Vec<u8>> {
        // Serialize the conditions to JSON exactly like lit-node does
        let conditions_json = if let Some(ref conditions) = params.unified_access_control_conditions {
            serde_json::to_string(conditions)?
        } else if let Some(ref conditions) = params.access_control_conditions {
            serde_json::to_string(conditions)?
        } else if let Some(ref conditions) = params.evm_contract_conditions {
            serde_json::to_string(conditions)?
        } else if let Some(ref conditions) = params.sol_rpc_conditions {
            serde_json::to_string(conditions)?
        } else {
            return Err(eyre!("No access control conditions provided"));
        };

        tracing::debug!("stringified_access_control_conditions: {:?}", conditions_json);

        // Hash the JSON string exactly like lit-node does
        let mut hasher = Sha256::new();
        hasher.update(conditions_json.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    /// Generate the identity parameter for encryption
    fn get_identity_param_for_encryption(
        &self,
        hash_of_conditions: &str,
        hash_of_private_data: &str,
    ) -> String {
        format!(
            "lit-accesscontrolcondition://{}/{}",
            hash_of_conditions, hash_of_private_data
        )
    }
}
