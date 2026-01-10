use std::fmt::Debug;

use crate::{
    AccessControlConditionResource, LitActionResource, LitResourcePrefix, PKPNFTResource,
    PaymentDelegationResource,
};

pub trait LitResource: Debug {
    /// Get the fully qualified IRI for this resource. This is compatible with the URI spec
    /// outlined here: https://datatracker.ietf.org/doc/html/rfc3986.
    fn get_resource_key(&self) -> String {
        format!(
            "{}://{}",
            self.get_resource_prefix(),
            self.get_resource_id()
        )
    }

    /// Get the identifier for this resource.
    fn get_resource_id(&self) -> &String;

    /// Get the prefix for this resource.
    fn get_resource_prefix(&self) -> LitResourcePrefix;
}

impl LitResource for AccessControlConditionResource {
    fn get_resource_id(&self) -> &String {
        self.get_resource_id()
    }

    fn get_resource_prefix(&self) -> LitResourcePrefix {
        LitResourcePrefix::ACC
    }
}

impl LitResource for PKPNFTResource {
    fn get_resource_id(&self) -> &String {
        self.get_resource_id()
    }

    fn get_resource_prefix(&self) -> LitResourcePrefix {
        LitResourcePrefix::PKP
    }
}

impl LitResource for LitActionResource {
    fn get_resource_id(&self) -> &String {
        self.get_resource_id()
    }

    fn get_resource_prefix(&self) -> LitResourcePrefix {
        LitResourcePrefix::LA
    }
}

impl LitResource for PaymentDelegationResource {
    fn get_resource_id(&self) -> &String {
        self.get_resource_id()
    }

    fn get_resource_prefix(&self) -> LitResourcePrefix {
        LitResourcePrefix::PD
    }
}
