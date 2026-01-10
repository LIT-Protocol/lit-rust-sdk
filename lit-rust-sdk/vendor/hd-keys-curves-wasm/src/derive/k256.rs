use lit_rust_crypto::{
    hash2curve::{ExpandMsgXmd, GroupDigest},
    k256::{Scalar, Secp256k1},
};

use crate::derive::HDDeriver;

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        Secp256k1::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}
