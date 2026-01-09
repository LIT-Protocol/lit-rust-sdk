use super::{LitAbility, LitResourceAbility, ResourceType};

#[derive(Clone, Debug, Default)]
pub struct AccessControlConditionResource {
    resource_id: String,
}

impl AccessControlConditionResource {
    pub fn new(resource_id: String) -> AccessControlConditionResource {
        AccessControlConditionResource { resource_id }
    }

    pub fn get_resource_id(&self) -> &String {
        &self.resource_id
    }

    pub fn decrypt_ability(&self) -> LitResourceAbility {
        LitResourceAbility {
            resource: ResourceType::AccessControlCondition(self.clone()),
            ability: LitAbility::AccessControlConditionDecryption,
        }
    }

    pub fn signing_ability(&self) -> LitResourceAbility {
        LitResourceAbility {
            resource: ResourceType::AccessControlCondition(self.clone()),
            ability: LitAbility::AccessControlConditionSigning,
        }
    }
}
