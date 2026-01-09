use crate::common::{EncryptedBroadcastRequest, NodeIdentityKey, Response, UrlPrefix};
use crate::{SdkError, SdkResult};
use lit_node_core::{
    AuthMethod, AuthSigItem, CurveType, NodeSet,
    request::JsonSignSessionKeyRequestV2,
    response::{GenericResponse, JsonSignSessionKeyResponseV2},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The response type for sign session key calls
pub type SignSessionKeyResponse = Response<GenericResponse<JsonSignSessionKeyResponseV2>>;

/// The sign session key request struct
pub type SignSessionKeyRequest = EncryptedBroadcastRequest<
    SignSessionKeyRequestBuilder,
    JsonSignSessionKeyRequestV2,
    GenericResponse<JsonSignSessionKeyResponseV2>,
>;

encrypted_builder!(
    SignSessionKeyRequestBuilder,
    JsonSignSessionKeyRequestV2,
    GenericResponse<JsonSignSessionKeyResponseV2>,
    "web/sign_session_key/v2"
);

impl SignSessionKeyRequestBuilder {
    builder_setter!(
        session_key,
        session_key,
        String,
        JsonSignSessionKeyRequestV2,
        session_key
    );
    builder_setter!(
        auth_methods,
        auth_methods,
        Vec<AuthMethod>,
        JsonSignSessionKeyRequestV2,
        auth_methods
    );
    builder_setter!(
        pkp_public_key,
        pkp_public_key,
        Option<String>,
        JsonSignSessionKeyRequestV2,
        pkp_public_key
    );
    builder_setter!(
        auth_sig,
        auth_sig,
        Option<AuthSigItem>,
        JsonSignSessionKeyRequestV2,
        auth_sig
    );
    builder_setter!(
        siwe_message,
        siwe_message,
        String,
        JsonSignSessionKeyRequestV2,
        siwe_message
    );
    builder_setter!(
        curve_type,
        curve_type,
        CurveType,
        JsonSignSessionKeyRequestV2,
        curve_type
    );
    builder_setter!(
        code,
        code,
        Option<String>,
        JsonSignSessionKeyRequestV2,
        code
    );
    builder_setter!(
        lit_action_ipfs_id,
        lit_action_ipfs_id,
        Option<String>,
        JsonSignSessionKeyRequestV2,
        lit_action_ipfs_id
    );
    builder_setter!(
        js_params,
        js_params,
        Option<serde_json::Value>,
        JsonSignSessionKeyRequestV2,
        js_params
    );
    builder_setter!(epoch, epoch, u64, JsonSignSessionKeyRequestV2, epoch);
    builder_setter!(
        inner_node_set,
        node_set,
        Vec<NodeSet>,
        JsonSignSessionKeyRequestV2,
        node_set
    );

    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        let Some(request) = &self.request else {
            return Ok(());
        };
        if request.session_key.is_empty() {
            return Err(SdkError::Build("No session_key is specified".to_string()));
        }
        Ok(())
    }
}
