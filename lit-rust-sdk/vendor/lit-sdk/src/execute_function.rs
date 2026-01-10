//! Execute Lit Action functions

use crate::common::{EncryptedMulticastRequest, EndpointRequest, Response, UrlPrefix};
use crate::{SdkError, SdkResult};
use lit_node_core::{
    request::JsonExecutionRequest,
    response::{GenericResponse, JsonExecutionResponse},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The response type for execute lit action functions
pub type ExecuteFunctionResponse = Response<GenericResponse<JsonExecutionResponse>>;

/// The request type for execute lit action functions
pub type ExecuteFunctionRequest = EncryptedMulticastRequest<
    ExecuteFunctionRequestBuilder,
    JsonExecutionRequest,
    GenericResponse<JsonExecutionResponse>,
>;

encrypted_multicast_builder!(
    ExecuteFunctionRequestBuilder,
    JsonExecutionRequest,
    GenericResponse<JsonExecutionResponse>,
    "/web/execute/v2"
);

impl ExecuteFunctionRequestBuilder {
    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        Ok(())
    }
}
