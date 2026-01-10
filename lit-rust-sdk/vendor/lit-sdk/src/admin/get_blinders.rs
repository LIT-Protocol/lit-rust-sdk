use crate::{AdminRequest, AdminResponse, SdkError, SdkResult, UrlPrefix};
use lit_node_core::{AdminAuthSig, Blinders, JsonAuthSig};
use std::{collections::HashMap, marker::PhantomData};

/// The response for getting the blinders
pub type GetBlindersResponse = AdminResponse<Blinders>;

/// The request for getting the blinders
pub type GetBlindersRequest = AdminRequest<GetBlindersBuilder, AdminAuthSig, Blinders>;

admin_builder!(
    GetBlindersBuilder,
    AdminAuthSig,
    Blinders,
    "/web/admin/get_blinders/v2"
);

impl GetBlindersBuilder {
    builder_setter!(auth_sig, auth_sig, JsonAuthSig, AdminAuthSig, auth_sig);

    /// Check the request before building
    fn request_checks(&self) -> SdkResult<()> {
        if self.request.is_none() {
            return Err(SdkError::Build("No auth sig is specified".to_string()));
        };
        Ok(())
    }
}
