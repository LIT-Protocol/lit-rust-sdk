use crate::derive::HDDeriver;
use lit_rust_crypto::{hash2curve::ExpandMsgXmd, pallas::Scalar};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(msg, dst)
    }
}
