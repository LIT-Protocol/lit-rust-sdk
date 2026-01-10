use lit_rust_crypto::{
    hash2curve::{ExpandMsgXmd, GroupDigest},
    p256::{NistP256, Scalar},
};

use crate::derive::HDDeriver;

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        NistP256::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}
