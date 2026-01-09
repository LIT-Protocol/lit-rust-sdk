use super::{LitAbility, LitResourceAbility, ResourceType};

#[derive(Clone, Debug, Default)]
pub struct PKPNFTResource {
    token_id: String,
}

impl PKPNFTResource {
    pub fn new(token_id: String) -> PKPNFTResource {
        PKPNFTResource { token_id }
    }

    pub fn get_resource_id(&self) -> &String {
        &self.token_id
    }

    pub fn signing_ability(&self) -> LitResourceAbility {
        LitResourceAbility {
            resource: ResourceType::PKPNFT(self.clone()),
            ability: LitAbility::PKPSigning,
        }
    }
}
