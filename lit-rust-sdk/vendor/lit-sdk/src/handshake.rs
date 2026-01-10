use crate::common::{Request, Response, UrlPrefix};
use crate::{SdkError, SdkResult};
use lit_node_core::{
    NodeSet,
    request::JsonSDKHandshakeRequest,
    response::{GenericResponse, JsonSDKHandshakeResponse},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The handshake request struct
pub type HandshakeRequest = Request<
    HandshakeRequestBuilder,
    JsonSDKHandshakeRequest,
    GenericResponse<JsonSDKHandshakeResponse>,
>;

/// The response type for handshake calls
pub type HandshakeResponse = Response<GenericResponse<JsonSDKHandshakeResponse>>;

basic_builder!(
    HandshakeRequestBuilder,
    JsonSDKHandshakeRequest,
    GenericResponse<JsonSDKHandshakeResponse>,
    "web/handshake"
);

impl HandshakeRequestBuilder {
    builder_setter!(
        client_public_key,
        client_public_key,
        String,
        JsonSDKHandshakeRequest,
        client_public_key
    );
    builder_setter!(
        challenge,
        challenge,
        Option<String>,
        JsonSDKHandshakeRequest,
        challenge
    );

    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        if let Some(request) = &self.request {
            if request.client_public_key.is_empty() {
                return Err(SdkError::Build(
                    "No client public key is specified".to_string(),
                ));
            }

            if let Some(challenge) = &request.challenge
                && challenge.is_empty()
            {
                return Err(SdkError::Build("No challenge is specified".to_string()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_request_fields() {
        let request = HandshakeRequest::new()
            .client_public_key("blah".to_string())
            .challenge("challenge".to_string())
            .node_set(vec![NodeSet {
                socket_address: "".to_string(),
                value: 0,
            }])
            .build()
            .unwrap();
        assert_eq!(request.inner.challenge, Some("challenge".to_string()));
        assert_eq!(request.inner.client_public_key, "blah".to_string());
    }

    #[test]
    fn set_request() {
        let request = HandshakeRequest::new()
            .request(JsonSDKHandshakeRequest {
                challenge: None,
                client_public_key: "blah".to_string(),
            })
            .node_set(vec![NodeSet {
                socket_address: "".to_string(),
                value: 0,
            }])
            .build()
            .unwrap();
        assert_eq!(request.inner.challenge, None);
        assert_eq!(request.inner.client_public_key, "blah".to_string());
    }
}
