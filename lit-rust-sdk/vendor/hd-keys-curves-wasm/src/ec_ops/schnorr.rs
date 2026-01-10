#[cfg(any(feature = "sha2", feature = "sha3", feature = "blake2"))]
use super::consts::*;
use core::marker::PhantomData;
use digest::{Digest, ExtendableOutput, Update};
use std::io::{Cursor, Read};

pub trait Challenge {
    fn compute_challenge(&self, r: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8>;
}

pub fn parse_hash(cursor: &mut Cursor<&[u8]>) -> Result<Box<dyn Challenge>, &'static str> {
    let mut hash = [0u8; 32];
    cursor
        .read_exact(&mut hash)
        .map_err(|_| "Invalid hash function")?;
    match &hash[..] {
        #[cfg(feature = "sha2")]
        HASH_NAME_SHA2_256 => Ok(Box::new(FixedDigest::<sha2::Sha256>(PhantomData))),
        #[cfg(feature = "sha2")]
        HASH_NAME_SHA2_384 => Ok(Box::new(FixedDigest::<sha2::Sha384>(PhantomData))),
        #[cfg(feature = "sha2")]
        HASH_NAME_SHA2_512 => Ok(Box::new(FixedDigest::<sha2::Sha512>(PhantomData))),
        #[cfg(feature = "sha3")]
        HASH_NAME_SHA3_256 => Ok(Box::new(FixedDigest::<sha3::Sha3_256>(PhantomData))),
        #[cfg(feature = "sha3")]
        HASH_NAME_SHA3_384 => Ok(Box::new(FixedDigest::<sha3::Sha3_384>(PhantomData))),
        #[cfg(feature = "sha3")]
        HASH_NAME_SHA3_512 => Ok(Box::new(FixedDigest::<sha3::Sha3_512>(PhantomData))),
        #[cfg(feature = "sha3")]
        HASH_NAME_KECCAK256 => Ok(Box::new(FixedDigest::<sha3::Keccak256>(PhantomData))),
        #[cfg(feature = "blake2")]
        HASH_NAME_BLAKE2B_512 => Ok(Box::new(FixedDigest::<blake2::Blake2b512>(PhantomData))),
        #[cfg(feature = "sha2")]
        HASH_NAME_TAPROOT => Ok(Box::new(Taproot)),
        #[cfg(feature = "sha3")]
        HASH_NAME_SHAKE128 => Ok(Box::new(ExtendableDigest::<sha3::Shake128> {
            output_size: 32,
            _marker: PhantomData,
        })),
        #[cfg(feature = "sha3")]
        HASH_NAME_SHAKE256 => Ok(Box::new(ExtendableDigest::<sha3::Shake256> {
            output_size: 64,
            _marker: PhantomData,
        })),
        _ => Err("Unsupported hash function"),
    }
}

#[cfg(feature = "sha2")]
#[derive(Copy, Clone, Debug)]
pub struct Taproot;

#[derive(Copy, Clone, Debug)]
pub struct FixedDigest<D: Digest>(PhantomData<D>);

#[derive(Copy, Clone, Debug)]
pub struct ExtendableDigest<D: Default + ExtendableOutput + Update> {
    output_size: usize,
    _marker: PhantomData<D>,
}

impl<D: Digest> Challenge for FixedDigest<D> {
    fn compute_challenge(&self, r: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hasher = D::new();
        hasher.update(r);
        hasher.update(pub_key);
        hasher.update(msg);
        hasher.finalize().to_vec()
    }
}

impl<D: Default + ExtendableOutput + Update> Challenge for ExtendableDigest<D> {
    fn compute_challenge(&self, r: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hasher = D::default();
        hasher.update(r);
        hasher.update(pub_key);
        hasher.update(msg);
        hasher.finalize_boxed(self.output_size).to_vec()
    }
}

#[cfg(feature = "sha2")]
impl Challenge for Taproot {
    fn compute_challenge(&self, r: &[u8], pub_key: &[u8], msg: &[u8]) -> Vec<u8> {
        use sha2::Digest;

        let tag_hash = sha2::Sha256::digest(b"BIP0340/challenge");
        let digest = sha2::Sha256::new();
        digest
            .chain_update(tag_hash)
            .chain_update(tag_hash)
            .chain_update(r)
            .chain_update(pub_key)
            .chain_update(msg)
            .finalize()
            .to_vec()
    }
}
