use crate::types::{
    ExecuteJsParams, ExecuteJsResponse, NodeShare, SessionSignature, SessionSignatures, SignedData,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use elliptic_curve::{scalar::IsHigh, subtle::ConditionallySelectable, PrimeField};
use eyre::Result;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use reqwest::Client;
use std::collections::HashMap;
use tracing::{debug, info, warn};

impl<P: alloy::providers::Provider> super::LitNodeClient<P> {
    pub async fn execute_js(&self, params: ExecuteJsParams) -> Result<ExecuteJsResponse> {
        if !self.ready {
            return Err(eyre::eyre!("Client not connected"));
        }
        if params.code.is_none() && params.ipfs_id.is_none() {
            return Err(eyre::eyre!("Either code or ipfsId must be provided"));
        }

        let request_id = self.generate_request_id();
        info!("Executing Lit Action with request ID: {}", request_id);

        let node_urls = self.connected_nodes();
        let min_responses = node_urls.len() * 2 / 3;
        let http_client = &self.http_client;

        let futures: Vec<_> = node_urls
            .iter()
            .map(|node_url| {
                let node_url = node_url.clone();
                let params = params.clone();
                let request_id = request_id.clone();
                async move {
                    let result =
                        Self::execute_js_node_request(http_client, &node_url, &params, &request_id)
                            .await;
                    (node_url, result)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        let mut node_responses = Vec::new();
        for (node_url, result) in results {
            match result {
                Ok(response) => {
                    info!("Got response from node: {}", node_url);
                    node_responses.push(response);
                }
                Err(e) => {
                    warn!("Failed to get response from node {}: {}", node_url, e);
                }
            }
        }

        if node_responses.len() < min_responses {
            return Err(eyre::eyre!(format!(
                "Not enough successful responses. Got {}, need {}",
                node_responses.len(),
                min_responses
            )));
        }

        let most_common_response = self.find_most_common_response(&node_responses)?;
        let has_signed_data = !most_common_response.signed_data.is_empty();
        let has_claim_data = !most_common_response.claim_data.is_empty();

        if most_common_response.success && !has_signed_data && !has_claim_data {
            return Ok(ExecuteJsResponse {
                claims: HashMap::new(),
                signatures: None,
                decryptions: vec![],
                response: most_common_response.response,
                logs: most_common_response.logs,
            });
        }

        if !has_signed_data && !has_claim_data {
            return Ok(ExecuteJsResponse {
                claims: HashMap::new(),
                signatures: None,
                decryptions: vec![],
                response: most_common_response.response,
                logs: most_common_response.logs,
            });
        }

        let combined_signatures = self.combine_ecdsa_signature_shares(&node_responses).await?;
        Ok(ExecuteJsResponse {
            claims: most_common_response.claim_data,
            signatures: combined_signatures,
            decryptions: vec![],
            response: most_common_response.response,
            logs: most_common_response.logs,
        })
    }

    async fn execute_js_node_request(
        http_client: &Client,
        node_url: &str,
        params: &ExecuteJsParams,
        request_id: &str,
    ) -> Result<NodeShare> {
        let endpoint = format!("{}/web/execute", node_url);
        let session_sig = Self::get_session_sig_by_url(&params.session_sigs, node_url)?;
        let mut request_body = serde_json::json!({ "authSig": session_sig });
        if let Some(code) = &params.code {
            let encoded_code = BASE64.encode(code.as_bytes());
            request_body["code"] = serde_json::Value::String(encoded_code);
        }
        if let Some(ipfs_id) = &params.ipfs_id {
            request_body["ipfsId"] = serde_json::Value::String(ipfs_id.clone());
        }
        if let Some(auth_methods) = &params.auth_methods {
            request_body["authMethods"] = serde_json::to_value(auth_methods)?;
        }
        if let Some(js_params) = &params.js_params {
            request_body["jsParams"] = js_params.clone();
        }
        debug!("Sending execute request to {}: {}", endpoint, request_body);

        let response = http_client
            .post(&endpoint)
            .header("X-Request-Id", request_id)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read body".to_string());
            warn!("Execute JS failed with status {}: {}", status, body);
            return Err(eyre::eyre!(format!("HTTP {} - {}", status, body)));
        }

        let response_body = response.text().await?;
        info!("Execute JS response from {}: {}", node_url, response_body);
        let node_response: NodeShare = serde_json::from_str(&response_body).map_err(|e| {
            warn!("Failed to parse execute JS response: {}", e);
            eyre::eyre!(e)
        })?;
        Ok(node_response)
    }

    fn find_most_common_response(&self, responses: &[NodeShare]) -> Result<NodeShare> {
        if responses.is_empty() {
            return Err(eyre::eyre!("No responses to find consensus from"));
        }
        for response in responses {
            if response.success {
                return Ok(response.clone());
            }
        }
        Ok(responses[0].clone())
    }

    fn get_session_sig_by_url(
        session_sigs: &SessionSignatures,
        url: &str,
    ) -> Result<SessionSignature> {
        if session_sigs.is_empty() {
            return Err(eyre::eyre!("You must pass in sessionSigs"));
        }
        let session_sig = session_sigs.get(url).ok_or_else(|| {
            eyre::eyre!(format!(
                "You passed sessionSigs but we could not find session sig for node {}",
                url
            ))
        })?;
        Ok(session_sig.clone())
    }

    async fn combine_ecdsa_signature_shares(
        &self,
        node_responses: &[NodeShare],
    ) -> Result<Option<serde_json::Value>> {
        let mut signatures_by_name: HashMap<String, Vec<SignedData>> = HashMap::new();
        for response in node_responses {
            if !response.success {
                continue;
            }
            for signed_data in response.signed_data.values() {
                let sig_name = signed_data.sig_name.clone();
                signatures_by_name
                    .entry(sig_name)
                    .or_default()
                    .push(signed_data.clone());
            }
        }
        if signatures_by_name.is_empty() {
            return Ok(None);
        }

        let mut combined_signatures = HashMap::new();
        for (sig_name, sig_shares) in signatures_by_name {
            let threshold = self.connected_nodes().len() * 2 / 3;
            if sig_shares.len() < threshold {
                warn!(
                    "Not enough signature shares for {}. Got {}, need {}",
                    sig_name,
                    sig_shares.len(),
                    threshold
                );
                continue;
            }
            let first_share = &sig_shares[0];
            if first_share.sig_type != "K256" {
                warn!("Unsupported signature type: {}", first_share.sig_type);
                continue;
            }

            let valid_shares: Vec<_> = sig_shares
                .iter()
                .filter(|share| share.data_signed != "fail" && !share.signature_share.is_empty())
                .cloned()
                .collect();
            if valid_shares.len() < threshold {
                warn!("Not enough valid signature shares for {}. Got {} valid shares (total {}), need {}", sig_name, valid_shares.len(), sig_shares.len(), threshold);
                continue;
            }
            info!(
                "Processing {} with {} valid shares out of {} total (threshold: {})",
                sig_name,
                valid_shares.len(),
                sig_shares.len(),
                threshold
            );

            let first_share = &valid_shares[0];
            let mut parsed_shares = Vec::new();
            let mut public_key = None;
            let mut presignature_big_r = None;
            let mut msg_hash = None;
            for share in &valid_shares {
                let sig_share: Result<Scalar> = serde_json::from_str(&share.signature_share)
                    .map_err(|e| eyre::eyre!(format!("Failed to parse signature share: {}", e)));
                if let Ok(sig_share) = sig_share {
                    parsed_shares.push(sig_share);
                    if public_key.is_none() {
                        public_key =
                            serde_json::from_str::<k256::AffinePoint>(&share.public_key).ok();
                        presignature_big_r =
                            serde_json::from_str::<k256::AffinePoint>(&share.big_r).ok();
                        msg_hash = serde_json::from_str::<Scalar>(&share.data_signed).ok();
                    }
                }
            }

            if parsed_shares.len() >= threshold {
                if let (Some(pub_key), Some(big_r), Some(hash)) =
                    (public_key, presignature_big_r, msg_hash)
                {
                    match self.combine_signature_shares_k256(parsed_shares, big_r) {
                        Ok((s, was_flipped)) => {
                            if self.verify_signature(&pub_key, &hash, &big_r, &s) {
                                info!(
                                    "Successfully combined and verified signature for {}",
                                    sig_name
                                );
                                let sig_json = self.convert_signature_to_response(
                                    &big_r,
                                    &s,
                                    was_flipped,
                                    &pub_key,
                                    &hash,
                                    first_share,
                                )?;
                                combined_signatures.insert(sig_name, sig_json);
                            } else {
                                warn!("Combined signature verification failed for {}", sig_name);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to combine signature shares for {}: {:?}",
                                sig_name, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "Missing required data to combine signatures for {}",
                        sig_name
                    );
                }
            }
        }

        if combined_signatures.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::to_value(combined_signatures).unwrap()))
        }
    }

    fn combine_signature_shares_k256(
        &self,
        signature_shares: Vec<Scalar>,
        _big_r: AffinePoint,
    ) -> Result<(Scalar, bool)> {
        if signature_shares.is_empty() {
            return Err(eyre::eyre!("No signature shares provided"));
        }
        let mut s: Scalar = signature_shares.into_iter().sum();
        let was_flipped = s.is_high().into();
        s.conditional_assign(&(-s), s.is_high());
        Ok((s, was_flipped))
    }

    fn verify_signature(
        &self,
        public_key: &AffinePoint,
        msg_hash: &Scalar,
        big_r: &AffinePoint,
        s: &Scalar,
    ) -> bool {
        use elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        let r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&big_r.x());
        if r.is_zero().into() || s.is_zero().into() {
            return false;
        }
        let s_inv = match Option::<Scalar>::from(s.invert()) {
            Some(inv) => inv,
            None => return false,
        };
        if msg_hash.is_zero().into() {
            return false;
        }
        let public_key_proj = ProjectivePoint::from(*public_key);
        let generator = ProjectivePoint::GENERATOR;
        let reproduced = (generator * (*msg_hash * s_inv)) + (public_key_proj * (r * s_inv));
        let reproduced_affine = reproduced.to_affine();
        let reproduced_r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&reproduced_affine.x());
        reproduced_r == r
    }

    fn convert_signature_to_response(
        &self,
        big_r: &AffinePoint,
        s: &Scalar,
        was_flipped: bool,
        _public_key: &AffinePoint,
        _msg_hash: &Scalar,
        first_share: &SignedData,
    ) -> Result<serde_json::Value> {
        use elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        let r = <Scalar as Reduce<k256::U256>>::reduce_bytes(&big_r.x());
        let r_hex = hex::encode(r.to_repr());
        let s_hex = hex::encode(s.to_repr());
        let mut recid = if big_r.y_is_odd().into() { 1u8 } else { 0u8 };
        if was_flipped {
            recid = 1 - recid;
        }
        let signature_hex = format!("0x{}{}", r_hex, s_hex);

        let public_key_clean = match serde_json::from_str::<String>(&first_share.public_key) {
            Ok(pk) => pk.strip_prefix("0x").unwrap_or(&pk).to_string(),
            Err(_) => first_share
                .public_key
                .strip_prefix("0x")
                .unwrap_or(&first_share.public_key)
                .to_string(),
        };
        let data_signed_clean = match serde_json::from_str::<String>(&first_share.data_signed) {
            Ok(ds) => ds,
            Err(_) => first_share.data_signed.clone(),
        };
        info!(
            "Converted signature for {}: r={}, s={}, recid={}, verified=true",
            first_share.sig_name,
            &r_hex[..16],
            &s_hex[..16],
            recid
        );
        Ok(
            serde_json::json!({ "r": r_hex, "s": s_hex, "recid": recid, "signature": signature_hex, "publicKey": public_key_clean, "dataSigned": data_signed_clean }),
        )
    }
}
