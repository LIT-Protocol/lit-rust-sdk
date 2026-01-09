use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::{
    ed448_goldilocks::{EdwardsPoint, Scalar},
    ff::PrimeField,
    group::GroupEncoding,
};
// NOTE: There is no difference between compressed and uncompressed points for
// this curve

impl CompressedBytes for EdwardsPoint {
    fn to_compressed(&self) -> Vec<u8> {
        self.compress().to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <EdwardsPoint as GroupEncoding>::Repr::default();
        if bytes.len() != repr.len() {
            return None;
        }
        repr.copy_from_slice(bytes);
        Option::from(Self::from_bytes(&repr))
    }
}

impl LeBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_bytes_rfc_8032().to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl BeBytes for Scalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut r = self.to_bytes_rfc_8032().to_vec();
        r.reverse();
        r
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        let mut r = bytes.to_vec();
        r.reverse();
        repr.copy_from_slice(&r);
        Option::from(Self::from_repr(repr))
    }
}

impl CompressedBytes for Scalar {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes_rfc_8032().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}
