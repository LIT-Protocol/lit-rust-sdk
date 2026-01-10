use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::{decaf377, ff::PrimeField, group::GroupEncoding};

// NOTE: There is no difference between compressed and uncompressed points for
// this curve

impl CompressedBytes for decaf377::Element {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <decaf377::Element as GroupEncoding>::Repr::default();
        if bytes.len() != repr.len() {
            return None;
        }
        repr.copy_from_slice(bytes);
        Option::from(Self::from_bytes(&repr))
    }
}

impl BeBytes for decaf377::Fr {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes.to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        let mut repr = <decaf377::Fr as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes.as_slice());
        Option::from(Self::from_repr(repr))
    }
}

impl LeBytes for decaf377::Fr {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = <decaf377::Fr as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl CompressedBytes for decaf377::Fr {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <decaf377::Fr as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}
