use crate::common::{EncryptedMulticastRequest, EndpointRequest, Response, UrlPrefix};
use crate::{SdkError, SdkResult};
use lit_node_core::{
    request::JsonPKPSigningRequest,
    response::{GenericResponse, JsonPKPSigningResponse},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The response type for pkp signing calls
pub type PKPSigningResponse = Response<GenericResponse<JsonPKPSigningResponse>>;

/// The pkp signing request struct
pub type PKPSigningRequest = EncryptedMulticastRequest<
    PKPSigningRequestBuilder,
    JsonPKPSigningRequest,
    GenericResponse<JsonPKPSigningResponse>,
>;

encrypted_multicast_builder!(
    PKPSigningRequestBuilder,
    JsonPKPSigningRequest,
    GenericResponse<JsonPKPSigningResponse>,
    "/web/pkp/sign/v2"
);

impl PKPSigningRequestBuilder {
    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        let Some(node_set) = &self.node_set else {
            return Ok(());
        };
        for (i, endpoint) in node_set.iter().enumerate() {
            if endpoint.body.pubkey.is_empty() {
                return Err(SdkError::Build(format!(
                    "No pubkey is specified at '{}'",
                    i + 1
                )));
            }
        }
        Ok(())
    }
}
