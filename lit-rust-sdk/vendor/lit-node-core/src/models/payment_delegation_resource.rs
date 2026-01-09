use super::{LitAbility, LitResourceAbility, ResourceType};

#[derive(Clone, Debug, Default)]
pub struct PaymentDelegationResource {
    token_id: String,
}

impl PaymentDelegationResource {
    pub fn new(token_id: String) -> PaymentDelegationResource {
        PaymentDelegationResource { token_id }
    }

    pub fn get_resource_id(&self) -> &String {
        &self.token_id
    }

    pub fn signing_ability(&self) -> LitResourceAbility {
        LitResourceAbility {
            resource: ResourceType::PaymentDelegation(self.clone()),
            ability: LitAbility::PaymentDelegationAuth,
        }
    }
}
