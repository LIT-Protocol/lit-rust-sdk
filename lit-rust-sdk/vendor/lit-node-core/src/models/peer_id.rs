use crate::{Error, Result};
use lit_rust_crypto::{
    blsful::inner_types as bls,
    curve25519_dalek, decaf377,
    ed448_goldilocks::{self, sha3},
    elliptic_curve::{
        bigint::{
            ArrayEncoding, ByteArray, Encoding, NonZero, Random, RandomMod, U256, U512, U768, U896,
        },
        ops::Reduce,
        rand_core::{CryptoRng, RngCore},
        scalar::FromUintUnchecked,
    },
    jubjub,
    k256::{
        self,
        sha2::{self, Digest},
    },
    p256, p384, pallas, vsss_rs,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};
use std::str::FromStr;

macro_rules! from_impl_peer_id {
    ($($primitive:ident),+$(,)*) => {
        $(
            impl TryFrom<$primitive> for PeerId {
                type Error = Error;

                fn try_from(value: $primitive) -> Result<Self> {
                    PeerId::try_from(U256::from(value))
                }
            }
        )+
    };
}

macro_rules! from_impl_nonzero_peer_id {
    ($($nonzero:ident => $primitive:ident),+$(,)*) => {
        $(
            impl TryFrom<PeerId> for $nonzero {
                type Error = Error;

                fn try_from(value: PeerId) -> Result<Self> {
                    let value = $primitive::try_from(value)?;
                    $nonzero::new(value).ok_or_else(|| Error::Parse("PeerId is zero".to_string()))
                }
            }

            impl TryFrom<&PeerId> for $nonzero {
                type Error = Error;

                fn try_from(value: &PeerId) -> Result<Self> {
                    Self::try_from(*value)
                }
            }
        )+
    };
}

from_impl_peer_id!(u128, u64, u32, u16, u8);
from_impl_nonzero_peer_id!(
    NonZeroUsize => usize,
    NonZeroU128 => u128,
    NonZeroU64 => u64,
    NonZeroU32 => u32,
    NonZeroU16 => u16,
    NonZeroU8 => u8,
);

pub trait FromPeerIdDirect {
    fn from_peer_id(peer_id: PeerId) -> Self;
}

/// PeerId is a unique identifier for a peer.
/// This represents a 256-bit number that can be compared, sorted, and hashed
/// rather than an address or random byte sequence.
/// Ideally, this is generated when the node peer is created and never changes.
/// 256-bits is more than enough to guarantee uniqueness. So why 256-bits?
/// Most protocols operate on ECC-scalars which are at least 256-bits.
/// This allows us to use the same data type for the peer id and the ECC scalar.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct PeerId(pub NonZero<U256>);

impl Serialize for PeerId {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_bytes(&self.0.to_be_byte_array())
        }
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let value = <&str>::deserialize(d)?;
            value.parse().map_err(serde::de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(d)?;
            PeerId::from_slice(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl Default for PeerId {
    fn default() -> Self {
        PeerId::NOT_ASSIGNED
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (*self.0).hash(state);
    }
}

impl TryFrom<U256> for PeerId {
    type Error = Error;

    fn try_from(value: U256) -> Result<Self> {
        Option::<PeerId>::from(NonZero::new(value).map(PeerId))
            .ok_or_else(|| Error::Parse("PeerId is zero".to_string()))
    }
}

impl TryFrom<&U256> for PeerId {
    type Error = Error;

    fn try_from(value: &U256) -> Result<Self> {
        PeerId::try_from(*value)
    }
}

impl From<PeerId> for U256 {
    fn from(value: PeerId) -> Self {
        *value.0
    }
}

impl From<&PeerId> for U256 {
    fn from(value: &PeerId) -> Self {
        *value.0
    }
}

impl From<PeerId> for ethers::types::U256 {
    fn from(value: PeerId) -> Self {
        ethers::types::U256::from(value.0.to_be_bytes())
    }
}

impl TryFrom<ethers::types::U256> for PeerId {
    type Error = Error;
    fn try_from(value: ethers::types::U256) -> Result<Self> {
        #[cfg(target_pointer_width = "32")]
        {
            Self::try_from(U256::from_words([
                value.0[0] as u32,
                (value.0[0] >> 32) as u32,
                value.0[1] as u32,
                (value.0[1] >> 32) as u32,
                value.0[2] as u32,
                (value.0[2] >> 32) as u32,
                value.0[3] as u32,
                (value.0[3] >> 32) as u32,
            ]))
        }
        #[cfg(target_pointer_width = "64")]
        Self::try_from(U256::from_words(value.0))
    }
}

impl TryFrom<usize> for PeerId {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self> {
        PeerId::try_from(U256::from_u64(value as u64))
    }
}

impl From<NonZeroU128> for PeerId {
    fn from(value: NonZeroU128) -> Self {
        PeerId(NonZero::from(value))
    }
}

impl From<NonZeroU64> for PeerId {
    fn from(value: NonZeroU64) -> Self {
        PeerId(NonZero::from(value))
    }
}

impl From<NonZeroU32> for PeerId {
    fn from(value: NonZeroU32) -> Self {
        PeerId(NonZero::from(value))
    }
}

impl From<NonZeroU16> for PeerId {
    fn from(value: NonZeroU16) -> Self {
        PeerId(NonZero::from(value))
    }
}

impl From<NonZeroU8> for PeerId {
    fn from(value: NonZeroU8) -> Self {
        PeerId(NonZero::from(value))
    }
}

impl TryFrom<PeerId> for usize {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        if value.0.bits() > 64 {
            return Err(Error::Parse(format!(
                "PeerId too large to convert to usize: {}",
                value.0
            )));
        }
        Ok(value.0.as_words()[0] as usize)
    }
}

impl TryFrom<&PeerId> for usize {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<PeerId> for u128 {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        if value.0.bits() > 128 {
            return Err(Error::Parse(format!(
                "PeerId too large to convert to u128: {}",
                value.0
            )));
        }
        let words = value.0.as_words();
        Ok((words[0] as u128) | ((words[1] as u128) << 64))
    }
}

impl TryFrom<&PeerId> for u128 {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<PeerId> for u64 {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        if value.0.bits() > 64 {
            return Err(Error::Parse(format!(
                "PeerId too large to convert to u64: {}",
                value.0
            )));
        }
        #[cfg(target_pointer_width = "32")]
        {
            let words = value.0.as_words();
            Ok((words[0] as u64) | ((words[1] as u64) << 32))
        }
        #[cfg(target_pointer_width = "64")]
        Ok(value.0.as_words()[0])
    }
}

impl TryFrom<&PeerId> for u64 {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<PeerId> for u32 {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        value.0.as_words()[0].try_into().map_err(|_| Error::Parse(format!("unable to convert PeerId '{}' to 32-bit integer. PeerId is too large to convert to u32", value)))
    }
}

impl TryFrom<&PeerId> for u32 {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<PeerId> for u16 {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        value.0.as_words()[0].try_into().map_err(|_| Error::Parse(format!("unable to convert PeerId '{}' to 16-bit integer. PeerId is too large to convert to u16", value)))
    }
}

impl TryFrom<&PeerId> for u16 {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<PeerId> for u8 {
    type Error = Error;

    fn try_from(value: PeerId) -> Result<Self> {
        value.0.as_words()[0].try_into().map_err(|_| Error::Parse(format!("unable to convert PeerId '{}' to 8-bit integer. PeerId is too large to convert to u8", value)))
    }
}

impl TryFrom<&PeerId> for u8 {
    type Error = Error;

    fn try_from(value: &PeerId) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<Vec<u8>> for PeerId {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&Vec<u8>> for PeerId {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

impl TryFrom<Box<[u8]>> for PeerId {
    type Error = Error;

    fn try_from(value: Box<[u8]>) -> Result<Self> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<&[u8; 32]> for PeerId {
    type Error = Error;

    fn try_from(value: &[u8; 32]) -> Result<Self> {
        Ok(PeerId::from_be_slice(value))
    }
}

impl TryFrom<[u8; 32]> for PeerId {
    type Error = Error;
    fn try_from(value: [u8; 32]) -> Result<Self> {
        Ok(PeerId::from_be_slice(&value))
    }
}

impl TryFrom<&ByteArray<U256>> for PeerId {
    type Error = Error;

    fn try_from(value: &ByteArray<U256>) -> Result<Self> {
        Self::try_from(*value)
    }
}

impl TryFrom<ByteArray<U256>> for PeerId {
    type Error = Error;

    fn try_from(value: ByteArray<U256>) -> Result<Self> {
        PeerId::try_from(U256::from_be_byte_array(value))
    }
}

impl From<PeerId> for Vec<u8> {
    fn from(value: PeerId) -> Self {
        value.0.to_be_byte_array().to_vec()
    }
}

impl From<&PeerId> for Vec<u8> {
    fn from(value: &PeerId) -> Self {
        value.0.to_be_byte_array().to_vec()
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self == &PeerId::NOT_ASSIGNED {
            return write!(f, "PeerId({})", self);
        }
        write!(f, "PeerId(NonZero(Uint({}))", self)
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self == &PeerId::NOT_ASSIGNED {
            return write!(f, "NotAssigned");
        }
        // Trim the leading zeros if any
        let bytes = self.0.to_be_byte_array();
        let mut index = bytes.len() - 1;
        for (i, byte) in bytes.iter().enumerate() {
            if *byte != 0 {
                index = i;
                break;
            }
        }
        let output = hex::encode(&bytes[index..]);
        index = output.chars().position(|c| c != '0').unwrap_or(0);
        write!(f, "{}", &output[index..])
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() > 64 {
            return Err(Error::Parse(format!(
                "PeerId too large to convert from string: PeerId: {}",
                s
            )));
        }
        let mut padded = s.to_string();
        if padded.len() & 1 == 1 {
            padded.insert(0, '0');
        }
        let bytes = hex::decode(padded)?;
        let mut array = [0u8; 32];
        let start = array.len().saturating_sub(bytes.len());
        array[start..].copy_from_slice(&bytes);
        PeerId::try_from(U256::from_be_slice(&array))
    }
}

impl From<PeerId> for k256::Scalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        <k256::Scalar as Reduce<U512>>::reduce(U512::from_be_byte_array(digest))
    }
}

impl From<PeerId> for k256::NonZeroScalar {
    fn from(value: PeerId) -> Self {
        let scalar = k256::Scalar::from(value);
        k256::NonZeroScalar::new(scalar).expect("scalar is somehow zero")
    }
}

impl From<PeerId> for p256::Scalar {
    fn from(value: PeerId) -> Self {
        const N: NonZero<U512> = NonZero::from_uint(U512::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ));
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        let wide_value = U512::from_be_byte_array(digest);
        let scalar = wide_value % N;
        let (_, lo) = scalar.split();

        p256::Scalar::from_uint_unchecked(lo)
    }
}

impl From<PeerId> for p256::NonZeroScalar {
    fn from(value: PeerId) -> Self {
        let scalar = p256::Scalar::from(value);
        p256::NonZeroScalar::new(scalar).expect("scalar is somehow zero")
    }
}

impl From<PeerId> for curve25519_dalek::Scalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        let digest: [u8; 64] = digest
            .as_slice()
            .try_into()
            .expect("digest is the wrong length");
        curve25519_dalek::Scalar::from_bytes_mod_order_wide(&digest)
    }
}

impl From<PeerId> for vsss_rs::curve25519::WrappedScalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        let digest: [u8; 64] = digest
            .as_slice()
            .try_into()
            .expect("digest is the wrong length");
        Self(vsss_rs::curve25519_dalek::Scalar::from_bytes_mod_order_wide(&digest))
    }
}

impl From<PeerId> for p384::Scalar {
    fn from(value: PeerId) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        const N: NonZero<U768> = NonZero::from_uint(U768::from_be_hex(
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        ));
        let mut hasher = sha3::Shake128::default();
        hasher.update(&value.0.to_be_byte_array());
        let digest = hasher.finalize_boxed(96);
        let wide_value = U768::from_be_slice(digest.as_ref());

        let scalar = wide_value % N;
        let (_, lo) = scalar.split();
        p384::Scalar::from_uint_unchecked(lo)
    }
}

impl From<PeerId> for p384::NonZeroScalar {
    fn from(value: PeerId) -> Self {
        let scalar = p384::Scalar::from(value);
        p384::NonZeroScalar::new(scalar).expect("scalar is somehow zero")
    }
}

impl From<PeerId> for ed448_goldilocks::Scalar {
    fn from(value: PeerId) -> Self {
        use sha3::digest::{ExtendableOutput, Update};

        let mut hasher = sha3::Shake128::default();
        hasher.update(&value.0.to_be_byte_array());
        let digest = hasher.finalize_boxed(114);
        let wide_bytes = ed448_goldilocks::WideScalarBytes::from_slice(digest.as_ref());
        <ed448_goldilocks::Scalar as Reduce<U896>>::reduce_bytes(wide_bytes)
    }
}

impl From<PeerId> for jubjub::Scalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        <jubjub::Scalar as Reduce<U512>>::reduce(U512::from_be_byte_array(digest))
    }
}

impl From<PeerId> for bls::Scalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        <bls::Scalar as Reduce<U512>>::reduce(U512::from_be_byte_array(digest))
    }
}

impl From<PeerId> for decaf377::Fr {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        Self::from_le_bytes_mod_order(&digest)
    }
}

impl From<PeerId> for pallas::Scalar {
    fn from(value: PeerId) -> Self {
        let digest = sha2::Sha512::digest(value.0.to_be_byte_array());
        let n = U512::from_be_byte_array(digest);
        Self::reduce(n)
    }
}

impl FromPeerIdDirect for k256::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(*peer_id.0.as_ref())
    }
}

impl FromPeerIdDirect for k256::NonZeroScalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        let scalar = k256::Scalar::from_peer_id(peer_id);
        // clippy error
        #[allow(dead_code)]
        struct NZScalar {
            scalar: k256::Scalar,
        }
        let t = NZScalar { scalar };
        unsafe { std::mem::transmute(t) }
    }
}

impl FromPeerIdDirect for p256::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(*peer_id.0.as_ref())
    }
}

impl FromPeerIdDirect for p256::NonZeroScalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        let scalar = p256::Scalar::from_peer_id(peer_id);
        // clippy error
        #[allow(dead_code)]
        struct NZScalar {
            scalar: p256::Scalar,
        }
        let t = NZScalar { scalar };
        unsafe { std::mem::transmute(t) }
    }
}

impl FromPeerIdDirect for p384::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(peer_id.0.as_ref().resize())
    }
}

impl FromPeerIdDirect for p384::NonZeroScalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        let scalar = p384::Scalar::from_peer_id(peer_id);
        // clippy error
        #[allow(dead_code)]
        struct NZScalar {
            scalar: p384::Scalar,
        }
        let t = NZScalar { scalar };
        unsafe { std::mem::transmute(t) }
    }
}

impl FromPeerIdDirect for curve25519_dalek::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(*peer_id.0.as_ref())
    }
}

impl FromPeerIdDirect for vsss_rs::curve25519::WrappedScalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(*peer_id.0.as_ref())
    }
}

impl FromPeerIdDirect for ed448_goldilocks::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(peer_id.0.as_ref().resize())
    }
}

impl FromPeerIdDirect for bls::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(peer_id.0.as_ref().resize())
    }
}

impl FromPeerIdDirect for jubjub::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        #[cfg(target_pointer_width = "32")]
        {
            let words = *peer_id.0.as_ref().as_words();
            let raw_words = [
                words[0] as u64 | (words[1] as u64) << 32,
                words[2] as u64 | (words[3] as u64) << 32,
                words[4] as u64 | (words[5] as u64) << 32,
                words[6] as u64 | (words[7] as u64) << 32,
            ];
            Self::from_raw(raw_words)
        }
        #[cfg(target_pointer_width = "64")]
        Self::from_raw(*peer_id.0.as_ref().as_words())
    }
}

impl FromPeerIdDirect for decaf377::Fr {
    fn from_peer_id(peer_id: PeerId) -> Self {
        let bytes = peer_id.0.as_ref().to_le_bytes();
        Self::from_bytes_checked(&bytes).expect("to be small enough to work")
    }
}

impl FromPeerIdDirect for pallas::Scalar {
    fn from_peer_id(peer_id: PeerId) -> Self {
        Self::from_uint_unchecked(*peer_id.0.as_ref())
    }
}

impl PeerId {
    pub const ONE: Self = PeerId(NonZero::<U256>::ONE);
    pub const NOT_ASSIGNED: Self = PeerId(NonZero::<U256>::from_uint(U256::MAX));

    pub fn is_not_assigned(&self) -> bool {
        self.0 == Self::NOT_ASSIGNED.0
    }

    pub const fn from_u8(value: u8) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u8(value)))
    }

    pub const fn from_u16(value: u16) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u16(value)))
    }

    pub const fn from_u32(value: u32) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u32(value)))
    }

    pub const fn from_u64(value: u64) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u64(value)))
    }

    pub const fn from_u128(value: u128) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u128(value)))
    }

    pub const fn from_usize(value: usize) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::from_u64(value as u64)))
    }

    /// Create a PeerId from a 256-bit value
    pub const fn from_be_slice(bytes: &[u8; 32]) -> Self {
        Self(NonZero::from_uint(U256::from_be_slice(bytes)))
    }

    pub fn from_slice(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::Parse("PeerId slice cannot be empty".to_string()));
        }
        let array = if value.len() > 32 {
            sha2::Sha512_256::digest(value).into()
        } else {
            let start = 32usize.saturating_sub(value.len());
            let mut array = [0u8; 32];
            array[start..].copy_from_slice(value);
            array
        };
        PeerId::try_from(U256::from_be_slice(&array))
    }

    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        PeerId(NonZero::<U256>::from_uint(U256::random(&mut rng)))
    }

    pub fn random_less_than(mut rng: impl RngCore + CryptoRng, upper: U256) -> Self {
        let upper = NonZero::new(upper).expect("upper bound must be non-zero");
        PeerId(NonZero::<U256>::from_uint(U256::random_mod(
            &mut rng, &upper,
        )))
    }
}

#[test]
fn test_parse_peer_id() {
    let peer_id = PeerId::random(vsss_rs::elliptic_curve::rand_core::OsRng);
    let u256: ethers::types::U256 = peer_id.into();
    let peer_id2 = u256.try_into().unwrap();
    assert_eq!(peer_id, peer_id2);
}

#[test]
fn test_into_scalar_pallas() {
    use rand_core::SeedableRng;

    let rng = rand_chacha::ChaChaRng::seed_from_u64(0);
    let peer_id = PeerId::random(rng);
    let id: pallas::Scalar = peer_id.into();
    let limbs = id.to_raw();
    assert_eq!(
        limbs,
        [
            0x3fd0ff79135bb946,
            0xcacf6941e56db2e4,
            0xa49547659cb1baa7,
            0x04e7181b6f5533de,
        ]
    );
}
