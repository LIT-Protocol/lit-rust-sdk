use super::AdminPlainResponse;
use crate::{AdminRequest, AdminResponse, SdkError, SdkResult, UrlPrefix};
use lit_node_core::{AdminAuthSig, Blinders};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

/// The response for setting the blinders
pub type SetBlindersResponse = AdminResponse<AdminPlainResponse>;

/// The request for setting the blinders
pub type SetBlindersRequest = AdminRequest<SetBlindersBuilder, SetBlindersData, AdminPlainResponse>;

admin_builder!(
    SetBlindersBuilder,
    SetBlindersData,
    AdminPlainResponse,
    "/web/admin/set_blinders/v2"
);

impl SetBlindersBuilder {
    builder_setter!(auth_sig, auth_sig, AdminAuthSig, SetBlindersData, auth_sig);
    builder_setter!(blinders, blinders, Blinders, SetBlindersData, blinders);

    fn request_checks(&self) -> SdkResult<()> {
        Ok(())
    }
}

/// The data used for setting the blinders
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SetBlindersData {
    /// The auth sig to use
    pub auth_sig: AdminAuthSig,
    /// The blinders to set
    pub blinders: Blinders,
}
