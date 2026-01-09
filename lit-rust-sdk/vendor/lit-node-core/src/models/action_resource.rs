use super::{LitAbility, LitResourceAbility, ResourceType};

#[derive(Clone, Debug, Default)]
pub struct LitActionResource {
    cid: String,
}

impl LitActionResource {
    pub fn new(cid: String) -> LitActionResource {
        LitActionResource { cid }
    }

    pub fn get_resource_id(&self) -> &String {
        &self.cid
    }

    pub fn execution_ability(&self) -> LitResourceAbility {
        LitResourceAbility {
            resource: ResourceType::LitAction(self.clone()),
            ability: LitAbility::LitActionExecution,
        }
    }
}
