use serde::{Deserialize, Serialize};

#[doc = "The different components that can be priced in the dynamic payment system."]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum LitActionPriceComponent {
    #[default]
    BaseAmount,
    RunTimeLength,
    MemoryUsage,
    CodeLength,
    ResponseLength,
    Signatures,
    Broadcasts,
    ContractCalls,
    CallDepth,
    Decrypts,
    Fetches,
}

impl From<LitActionPriceComponent> for u8 {
    fn from(value: LitActionPriceComponent) -> Self {
        match value {
            LitActionPriceComponent::BaseAmount => 0,
            LitActionPriceComponent::RunTimeLength => 1,
            LitActionPriceComponent::MemoryUsage => 2,
            LitActionPriceComponent::CodeLength => 3,
            LitActionPriceComponent::ResponseLength => 4,
            LitActionPriceComponent::Signatures => 5,
            LitActionPriceComponent::Broadcasts => 6,
            LitActionPriceComponent::ContractCalls => 7,
            LitActionPriceComponent::CallDepth => 8,
            LitActionPriceComponent::Decrypts => 9,
            LitActionPriceComponent::Fetches => 10,
        }
    }
}

#[doc = "Converts a u8 to a LitActionPriceComponent, or returns an error if the value is invalid."]
impl TryFrom<u8> for LitActionPriceComponent {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LitActionPriceComponent::BaseAmount),
            1 => Ok(LitActionPriceComponent::RunTimeLength),
            2 => Ok(LitActionPriceComponent::MemoryUsage),
            3 => Ok(LitActionPriceComponent::CodeLength),
            4 => Ok(LitActionPriceComponent::ResponseLength),
            5 => Ok(LitActionPriceComponent::Signatures),
            6 => Ok(LitActionPriceComponent::Broadcasts),
            7 => Ok(LitActionPriceComponent::ContractCalls),
            8 => Ok(LitActionPriceComponent::CallDepth),
            9 => Ok(LitActionPriceComponent::Decrypts),
            10 => Ok(LitActionPriceComponent::Fetches),
            _ => Err(format!("Invalid lit action price component: {value}")),
        }
    }
}
