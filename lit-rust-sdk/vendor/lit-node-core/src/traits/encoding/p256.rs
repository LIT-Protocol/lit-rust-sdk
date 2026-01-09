use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::{
    elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    ff::PrimeField,
    p256::{AffinePoint, FieldBytes, NistP256, NonZeroScalar, ProjectivePoint, Scalar, ecdsa},
};

impl CompressedBytes for ProjectivePoint {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_encoded_point(true).to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Option::from(Self::from_encoded_point(&pt))
    }

    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_encoded_point(false).to_bytes().to_vec()
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Option::from(Self::from_encoded_point(&pt))
    }
}

impl CompressedBytes for AffinePoint {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_encoded_point(true).to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Option::from(Self::from_encoded_point(&pt))
    }

    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_encoded_point(false).to_bytes().to_vec()
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Option::from(Self::from_encoded_point(&pt))
    }
}

impl CompressedBytes for ecdsa::VerifyingKey {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_encoded_point(true).to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Self::from_encoded_point(&pt).ok()
    }
    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_encoded_point(false).to_bytes().to_vec()
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        let pt = EncodedPoint::<NistP256>::from_bytes(bytes).ok()?;
        Self::from_encoded_point(&pt).ok()
    }
}

impl BeBytes for Scalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl LeBytes for Scalar {}

impl CompressedBytes for Scalar {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl BeBytes for NonZeroScalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(bytes);
        Option::from(Self::from_repr(repr))
    }
}

impl LeBytes for NonZeroScalar {}

impl BeBytes for ecdsa::SigningKey {
    fn to_be_bytes(&self) -> Vec<u8> {
        self.as_nonzero_scalar().to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = FieldBytes::default();
        repr.copy_from_slice(bytes);
        Self::from_bytes(&repr).ok()
    }
}

impl LeBytes for ecdsa::SigningKey {}
