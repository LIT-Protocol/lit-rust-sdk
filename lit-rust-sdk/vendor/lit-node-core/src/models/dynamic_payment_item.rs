use crate::LitActionPriceComponent;
use serde::{Deserialize, Serialize};

#[doc = "A single item in the dynamic payment struct."]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicPaymentItem {
    pub component: LitActionPriceComponent,
    pub quantity: u64,
    pub price: u64,
}
