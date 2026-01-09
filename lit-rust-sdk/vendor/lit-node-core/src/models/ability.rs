use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LitAbility {
    // Used by top level auth sigs
    AccessControlConditionDecryption,
    AccessControlConditionSigning,
    PKPSigning,
    LitActionExecution,
    PaymentDelegationAuth,
}

impl fmt::Display for LitAbility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LitAbility::AccessControlConditionDecryption => {
                write!(f, "access-control-condition-decryption")
            }
            LitAbility::AccessControlConditionSigning => {
                write!(f, "access-control-condition-signing")
            }
            LitAbility::PKPSigning => write!(f, "pkp-signing"),
            LitAbility::LitActionExecution => write!(f, "lit-action-execution"),
            LitAbility::PaymentDelegationAuth => write!(f, "lit-payment-delegation"),
        }
    }
}
