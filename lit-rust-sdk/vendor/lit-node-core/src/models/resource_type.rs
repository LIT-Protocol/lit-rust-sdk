use super::{
    AccessControlConditionResource, LitActionResource, PKPNFTResource, PaymentDelegationResource,
};

#[derive(Clone, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum ResourceType {
    AccessControlCondition(AccessControlConditionResource),
    PKPNFT(PKPNFTResource),
    LitAction(LitActionResource),
    PaymentDelegation(PaymentDelegationResource),
}
