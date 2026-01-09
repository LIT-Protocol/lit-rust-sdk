use crate::{AdminRequest, AdminResponse, SdkError, SdkResult, UrlPrefix};
use lit_node_core::AdminAuthSig;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

/// The parameters to pass for downloading a key backup
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyBackupParameters {
    /// The admin auth sig
    pub auth: AdminAuthSig,
    /// The epoch for which to download the backup
    pub epoch: u64,
}

/// The response for getting the key backup
pub type GetKeyBackupResponse = AdminResponse<()>;

/// The request for getting the key backup
pub type GetKeyBackupRequest = AdminRequest<GetKeyBackupBuilder, GetKeyBackupParameters, ()>;

admin_builder!(
    GetKeyBackupBuilder,
    GetKeyBackupParameters,
    (),
    "/web/admin/get_key_backup/v2"
);

impl GetKeyBackupBuilder {
    fn request_checks(&self) -> SdkResult<()> {
        let Some(request) = &self.request else {
            return Err(SdkError::Build("No auth sig is specified".to_string()));
        };
        if request.epoch < 2 {
            return Err(SdkError::Build("Invalid epoch".to_string()));
        }
        Ok(())
    }
}
