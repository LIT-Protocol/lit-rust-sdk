use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::{
    group::GroupEncoding,
    pallas::{Point, Scalar},
};

impl CompressedBytes for Point {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Point as GroupEncoding>::Repr::default();
        if repr.len() != bytes.len() {
            return None;
        }
        repr.copy_from_slice(bytes);
        Option::from(Self::from_bytes(&repr))
    }
}

impl BeBytes for Scalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        Option::from(Self::from_be_bytes(&bytes.try_into().ok()?))
    }
}

impl LeBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        Option::from(Self::from_le_bytes(bytes.try_into().ok()?))
    }
}

impl CompressedBytes for Scalar {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        Option::from(Self::from_le_bytes(bytes.try_into().ok()?))
    }
}
