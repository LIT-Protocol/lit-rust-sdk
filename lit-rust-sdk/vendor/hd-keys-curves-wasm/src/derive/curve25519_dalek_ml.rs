use crate::derive::HDDeriver;
use lit_rust_crypto::{
    curve25519_dalek::Scalar,
    hash2curve::{ExpandMsg, ExpandMsgXmd, Expander},
    vsss_rs::{curve25519::WrappedScalar, curve25519_dalek},
};

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<sha2::Sha512>::expand_message(&msg, &dst, 64)
            .expect("expand_message failed");
        let mut okm = [0u8; 64];
        expander.fill_bytes(&mut okm);
        Scalar::from_bytes_mod_order_wide(&okm)
    }
}

impl HDDeriver for WrappedScalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<sha2::Sha512>::expand_message(&msg, &dst, 64)
            .expect("expand_message failed");
        let mut okm = [0u8; 64];
        expander.fill_bytes(&mut okm);
        Self(curve25519_dalek::Scalar::from_bytes_mod_order_wide(&okm))
    }
}
