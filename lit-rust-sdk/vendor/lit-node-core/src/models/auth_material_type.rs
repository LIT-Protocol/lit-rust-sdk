use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum AuthMaterialType {
    #[default]
    /// This is an auth sig that was derived via a wallet.
    WalletSig,

    /// This is an auth sig that was derived via EIP 1271.
    ContractSig,

    /// This is an auth sig that was derived via session keys.
    SessionSig,

    /// This is an auth sig that was signed by the BLS network key
    BLSNetworkSig,
}
