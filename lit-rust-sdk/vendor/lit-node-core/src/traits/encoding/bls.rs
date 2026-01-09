use super::{BeBytes, CompressedBytes, LeBytes};
use lit_rust_crypto::blsful::inner_types::{G1Projective, G2Projective, Scalar};

impl CompressedBytes for G1Projective {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let bytes: [u8; 48] = bytes.try_into().ok()?;
        Option::from(Self::from_compressed(&bytes))
    }
    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_uncompressed().to_vec()
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        let bytes: [u8; 96] = bytes.try_into().ok()?;
        Option::from(Self::from_uncompressed(&bytes))
    }
}

impl CompressedBytes for G2Projective {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 96 {
            return None;
        }
        let bytes: [u8; 96] = bytes.try_into().ok()?;
        Option::from(Self::from_compressed(&bytes))
    }
    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_uncompressed().to_vec()
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 192 {
            return None;
        }
        let bytes: [u8; 192] = bytes.try_into().ok()?;
        Option::from(Self::from_uncompressed(&bytes))
    }
}

impl BeBytes for Scalar {
    fn to_be_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        Option::from(Scalar::from_be_bytes(bytes.try_into().ok()?))
    }
}

impl LeBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        Option::from(Scalar::from_le_bytes(bytes.try_into().ok()?))
    }
}

impl CompressedBytes for Scalar {
    fn to_compressed(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        Option::from(Scalar::from_be_bytes(bytes.try_into().ok()?))
    }
}
