pub mod request;
pub mod response;

mod ability;
mod access_control_condition_resource;
mod action_price_component;
mod action_resource;
mod attestation;
mod auth_material_type;
mod auth_method;
mod auth_sig;
mod auth_sig_item;
mod blinders;
mod control_condition_item;
mod curve_type;
mod dynamic_payment_item;
mod endpoint_version;
mod invocation;
mod multiple_auth_sigs;
mod node_set;
mod payment_delegation_resource;
mod peer_id;
mod pkp_nft_resource;
mod resource_ability;
mod resource_ability_request;
mod resource_ability_request_resource;
mod resource_prefix;
mod resource_type;
mod signable;
mod signed_data;
mod signing_scheme;

pub use ability::*;
pub use access_control_condition_resource::*;
pub use action_price_component::*;
pub use action_resource::*;
pub use attestation::*;
pub use auth_material_type::*;
pub use auth_method::*;
pub use auth_sig::*;
pub use auth_sig_item::*;
pub use blinders::*;
pub use control_condition_item::*;
pub use curve_type::*;
pub use dynamic_payment_item::*;
pub use endpoint_version::*;
pub use invocation::*;
pub use multiple_auth_sigs::*;
pub use node_set::*;
pub use payment_delegation_resource::*;
pub use peer_id::*;
pub use pkp_nft_resource::*;
pub use resource_ability::*;
pub use resource_ability_request::*;
pub use resource_ability_request_resource::*;
pub use resource_prefix::*;
pub use resource_type::*;
pub use signable::*;
pub use signed_data::*;
pub use signing_scheme::*;

pub(crate) fn default_epoch() -> u64 {
    0 // this will indicate to the nodes that a valid value isn't coming from the SDK.
}
