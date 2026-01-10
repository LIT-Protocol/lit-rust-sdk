use crate::derive::HDDeriver;
use lit_rust_crypto::{ed448_goldilocks::Scalar, hash2curve::ExpandMsgXof};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXof<sha3::Shake256>>(msg, dst)
    }
}
