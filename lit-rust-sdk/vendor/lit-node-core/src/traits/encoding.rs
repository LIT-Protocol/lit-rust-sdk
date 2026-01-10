mod bls;
mod curve25519;
mod decaf377;
mod ed448;
mod k256;
mod p256;
mod p384;
mod redjubjub;
mod redpallas;

/// A trait for handling points in compressed form.
pub trait CompressedBytes: Sized {
    /// Convert the point to compressed bytes.
    fn to_compressed(&self) -> Vec<u8>;

    /// Convert the point from compressed bytes.
    fn from_compressed(bytes: &[u8]) -> Option<Self>;
    /// Convert the point to uncompressed bytes.
    fn to_uncompressed(&self) -> Vec<u8> {
        self.to_compressed()
    }

    /// Convert the point from uncompressed bytes.
    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        Self::from_compressed(bytes)
    }
}

pub trait CompressedHex: Sized {
    /// Convert the point to compressed hex.
    fn to_compressed_hex(&self) -> String;

    /// Convert the point from compressed hex.
    fn from_compressed_hex(hex: &str) -> Option<Self>;

    /// Convert the point to uncompressed hex.
    fn to_uncompressed_hex(&self) -> String;

    /// Convert the point from uncompressed hex.
    fn from_uncompressed_hex(hex: &str) -> Option<Self>;
}

pub trait BeBytes: Sized {
    fn to_be_bytes(&self) -> Vec<u8>;

    fn from_be_bytes(bytes: &[u8]) -> Option<Self>;
}

pub trait LeBytes: BeBytes {
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = self.to_be_bytes();
        out.reverse();
        out
    }

    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        Self::from_be_bytes(&bytes)
    }
}

#[allow(dead_code)]
pub trait BeHex: Sized {
    fn to_be_hex(&self) -> String;

    fn from_be_hex(hex: &str) -> Option<Self>;
}

#[allow(dead_code)]
pub trait LeHex: Sized {
    fn to_le_hex(&self) -> String;

    fn from_le_hex(hex: &str) -> Option<Self>;
}

impl<B: BeBytes> BeHex for B {
    fn to_be_hex(&self) -> String {
        hex::encode(self.to_be_bytes())
    }

    fn from_be_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        Self::from_be_bytes(&bytes)
    }
}

impl<B: LeBytes> LeHex for B {
    fn to_le_hex(&self) -> String {
        hex::encode(self.to_le_bytes())
    }

    fn from_le_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        Self::from_le_bytes(&bytes)
    }
}

impl<P: CompressedBytes> CompressedHex for P {
    fn to_compressed_hex(&self) -> String {
        hex::encode(self.to_compressed())
    }

    fn from_compressed_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        Self::from_compressed(&bytes)
    }
    fn to_uncompressed_hex(&self) -> String {
        hex::encode(self.to_uncompressed())
    }

    fn from_uncompressed_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        Self::from_uncompressed(&bytes)
    }
}
