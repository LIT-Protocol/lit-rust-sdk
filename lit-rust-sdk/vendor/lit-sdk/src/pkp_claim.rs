use crate::common::{EncryptedMulticastRequest, EndpointRequest, Response, UrlPrefix};
use crate::{SdkError, SdkResult};
use lit_node_core::{
    request::JsonPKPClaimKeyRequest,
    response::{GenericResponse, JsonPKPClaimKeyResponse},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The response type for pkp claim calls
pub type PKPClaimKeyResponse = Response<GenericResponse<JsonPKPClaimKeyResponse>>;

/// The pkp claim request struct
pub type PKPClaimKeyRequest = EncryptedMulticastRequest<
    PKPClaimKeyRequestBuilder,
    JsonPKPClaimKeyRequest,
    GenericResponse<JsonPKPClaimKeyResponse>,
>;

encrypted_multicast_builder!(
    PKPClaimKeyRequestBuilder,
    JsonPKPClaimKeyRequest,
    GenericResponse<JsonPKPClaimKeyResponse>,
    "/web/pkp/claim"
);

impl PKPClaimKeyRequestBuilder {
    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        Ok(())
    }
}
