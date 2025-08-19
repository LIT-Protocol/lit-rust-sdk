#![allow(clippy::too_many_arguments)]

use alloy::sol;

sol!(// `all_derives` - derives standard Rust traits.
    #![sol(all_derives)]
    // `extra_derives` - derives additional traits by specifying their path.
    #![sol(extra_derives(serde::Serialize, serde::Deserialize))]
    #[sol(rpc)]
    Staking,
    "src/blockchain/abis/Staking.json"
);
