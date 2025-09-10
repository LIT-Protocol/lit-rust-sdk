use crate::client::LitNodeClient;
use crate::types::{
    DecryptRequest, DecryptResponse, EncryptionSignRequest, EncryptionSignResponse,
};
use alloy::providers::Provider as ProviderTrait;
use eyre::{eyre, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

impl<P> LitNodeClient<P>
where
    P: ProviderTrait,
{
    /// Decrypt data using BLS decryption with access control conditions
    /// This retrieves decryption shares from nodes and combines them client-side
    ///
    /// # Arguments
    ///
    /// * `params` - The decryption request containing the ciphertext and access control conditions
    ///
    /// # Returns
    ///
    /// * `Result<DecryptResponse>` - The decrypted data
    pub async fn decrypt(&self, params: DecryptRequest) -> Result<DecryptResponse> {
        // Validate that client is ready
        if !self.ready {
            return Err(eyre!(
                "LitNodeClient is not ready. Please call await client.connect() first."
            ));
        }

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

        // Get current epoch
        let epoch = self.epoch.as_ref().ok_or_else(|| eyre!("Epoch not set"))?;
        let epoch_number = epoch.number.try_into().unwrap_or(0);

        // Retrieve decryption shares from nodes
        let decryption_shares = self
            .retrieve_decryption_shares(&params, epoch_number)
            .await?;

        info!(
            "Retrieved {} decryption shares from nodes",
            decryption_shares.len()
        );

        // Get the network public key for verification
        let network_pub_key = self
            .network_pub_key
            .as_ref()
            .ok_or_else(|| eyre!("network_pub_key not set"))?;

        // Get identity parameter for decryption
        let hash_of_conditions = self.get_hashed_access_control_conditions_from_decrypt(&params)?;
        let hash_of_conditions_str = hex::encode(&hash_of_conditions);
        let identity_param = self
            .get_identity_param_for_encryption(&hash_of_conditions_str, &params.data_to_encrypt_hash);
        
        debug!("Identity param for decryption: {}", identity_param);

        // Combine shares and decrypt
        let decrypted_data = self.verify_and_decrypt_shares(
            network_pub_key,
            &identity_param,
            &params.ciphertext,
            decryption_shares,
        )?;

        Ok(DecryptResponse { decrypted_data })
    }

    /// Retrieve decryption shares from all connected nodes
    async fn retrieve_decryption_shares(
        &self,
        params: &DecryptRequest,
        epoch: u64,
    ) -> Result<Vec<EncryptionSignResponse>> {
        let nodes: Vec<_> = self.connection_state.iter().collect();
        let mut shares = Vec::new();

        for node in nodes {
            let url = node.url.clone();
            let session_sig = params
                .session_sigs
                .get(&url)
                .ok_or_else(|| eyre!("No session signature for node: {}", url))?;

            // Convert SessionSignature to AuthSig
            let auth_sig = crate::types::AuthSig {
                sig: session_sig.sig.clone(),
                derived_via: session_sig.derived_via.clone(),
                signed_message: session_sig.signed_message.clone(),
                address: session_sig.address.clone(),
                algo: session_sig.algo.clone(),
            };

            let request = EncryptionSignRequest {
                access_control_conditions: params.access_control_conditions.clone(),
                evm_contract_conditions: params.evm_contract_conditions.clone(),
                sol_rpc_conditions: params.sol_rpc_conditions.clone(),
                unified_access_control_conditions: params.unified_access_control_conditions.clone(),
                chain: params.chain.clone(),
                data_to_encrypt_hash: params.data_to_encrypt_hash.clone(),
                auth_sig,
                epoch,
            };

            let response = self.send_encryption_sign_request(&url, request).await?;
            shares.push(response);
        }

        Ok(shares)
    }

    /// Send encryption/sign request to a single node
    async fn send_encryption_sign_request(
        &self,
        node_url: &str,
        request: EncryptionSignRequest,
    ) -> Result<EncryptionSignResponse> {
        let url = format!("{}/web/encryption/sign", node_url);
        debug!("Sending encryption sign request to: {}", url);

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(eyre!(
                "Failed to get decryption share from {}: {}",
                node_url,
                error_text
            ));
        }

        let result: EncryptionSignResponse = response.json().await?;
        Ok(result)
    }

    /// Verify and decrypt using BLS shares
    fn verify_and_decrypt_shares(
        &self,
        _network_pub_key: &str,
        _identity_param: &str,
        ciphertext: &str,
        shares: Vec<EncryptionSignResponse>,
    ) -> Result<Vec<u8>> {
        // Decode base64 ciphertext
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let ciphertext_bytes = STANDARD.decode(ciphertext)?;

        // Combine shares into a single signature
        let signature_shares: Vec<blsful::SignatureShare<blsful::Bls12381G2Impl>> = shares
            .into_iter()
            .map(|s| s.signature_share)
            .collect();

        let combined_signature = blsful::Signature::from_shares(&signature_shares)?;

        // Serialize the signature for decryption
        let sig_bytes = serde_bare::to_vec(&combined_signature)?;

        // Decrypt the ciphertext using the combined signature
        let decrypted = crate::bls::decrypt(&ciphertext_bytes, &sig_bytes)?;

        Ok(decrypted)
    }

    /// Hash the access control conditions from decrypt request
    fn get_hashed_access_control_conditions_from_decrypt(
        &self,
        params: &DecryptRequest,
    ) -> Result<Vec<u8>> {
        // Serialize the conditions to JSON exactly like lit-node does
        let conditions_json =
            if let Some(ref conditions) = params.unified_access_control_conditions {
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

        debug!(
            "stringified_access_control_conditions: {:?}",
            conditions_json
        );

        // Hash the JSON string exactly like lit-node does
        let mut hasher = Sha256::new();
        hasher.update(conditions_json.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

}