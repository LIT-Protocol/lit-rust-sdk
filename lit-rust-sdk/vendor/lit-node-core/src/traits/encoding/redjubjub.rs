use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::{
    ff::PrimeField,
    group::GroupEncoding,
    jubjub::{Scalar, SubgroupPoint},
};

impl CompressedBytes for SubgroupPoint {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <SubgroupPoint as GroupEncoding>::Repr::default();
        if bytes.len() != repr.len() {
            return None;
        }
        repr.copy_from_slice(bytes);
        Option::from(Self::from_bytes(&repr))
    }
}

impl BeBytes for Scalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes.to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes.as_slice());
        Option::from(Self::from_repr(repr))
    }
}

impl LeBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl CompressedBytes for Scalar {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}
