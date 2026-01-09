use super::{LitAbility, ResourceType};

/// A `LitResourceAbility` specifies a LIT-specific ability that
/// is requested to be performed on a resource.
///
/// Since this struct can only be created from a LIT-specific resource
/// (eg. `AccessControlConditionResource` or `PKPNFTResource`) it is
/// guaranteed that the ability is compatible with the resource. For example,
/// a `PKPNFTResource` can only be used for signing, and an `AccessControlConditionResource`
/// can only be used for decryption or signing.
///
/// For example, to create a `LitResourceAbility` for a `PKPNFTResource` that
/// can be used for signing:
/// ```
/// let resource = super::PKPNFTResource::new("123".to_string());
/// let resource_ability = resource.sign_ability();
/// ```
#[derive(Debug, Clone)]
pub struct LitResourceAbility {
    pub(crate) resource: ResourceType,
    pub(crate) ability: LitAbility,
}

impl LitResourceAbility {
    pub fn get_resource(&self) -> &ResourceType {
        &self.resource
    }

    pub fn get_ability(&self) -> &LitAbility {
        &self.ability
    }
}
