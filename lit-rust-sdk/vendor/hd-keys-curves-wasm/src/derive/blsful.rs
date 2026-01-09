use lit_rust_crypto::{blsful::inner_types::Scalar, hash2curve::ExpandMsgXmd};

use crate::derive::HDDeriver;

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst)
    }
}
