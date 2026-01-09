mod compatibility;

use crate::{ByteOrder, Error, Scheme, is_zero};
use frost_core::Ciphersuite;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Display, Formatter};

/// A FROST participant identifier.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct Identifier {
    /// The scheme associated with this identifier.
    pub scheme: Scheme,
    /// The identifier value.
    pub id: Vec<u8>,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "scheme: {}, id: {}", self.scheme, hex::encode(&self.id))
    }
}

impl From<(Scheme, Vec<u8>)> for Identifier {
    fn from((scheme, id): (Scheme, Vec<u8>)) -> Self {
        Self { scheme, id }
    }
}

impl From<(Scheme, u128)> for Identifier {
    fn from((scheme, id): (Scheme, u128)) -> Self {
        let scalar_len = scheme.scalar_len().expect("Invalid ciphersuite");
        let mut bytes = vec![0u8; scalar_len];
        match scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                let int_bytes = id.to_be_bytes();
                bytes[scalar_len - int_bytes.len()..].copy_from_slice(&int_bytes);
            }
            ByteOrder::LittleEndian => {
                let int_bytes = id.to_le_bytes();
                bytes[..int_bytes.len()].copy_from_slice(&int_bytes);
            }
        }
        Self { scheme, id: bytes }
    }
}

impl From<(Scheme, u64)> for Identifier {
    fn from((scheme, id): (Scheme, u64)) -> Self {
        Self::from((scheme, id as u128))
    }
}

impl From<(Scheme, u32)> for Identifier {
    fn from((scheme, id): (Scheme, u32)) -> Self {
        Self::from((scheme, id as u128))
    }
}

impl From<(Scheme, u16)> for Identifier {
    fn from((scheme, id): (Scheme, u16)) -> Self {
        Self::from((scheme, id as u128))
    }
}

impl From<(Scheme, u8)> for Identifier {
    fn from((scheme, id): (Scheme, u8)) -> Self {
        Self::from((scheme, id as u128))
    }
}

impl<C: Ciphersuite> From<frost_core::Identifier<C>> for Identifier {
    fn from(s: frost_core::Identifier<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Identifier<C>> for Identifier {
    fn from(s: &frost_core::Identifier<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            id: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<Identifier> for frost_core::Identifier<C> {
    type Error = Error;

    fn try_from(s: Identifier) -> Result<Self, Self::Error> {
        Self::try_from(&s)
    }
}

impl<C: Ciphersuite> TryFrom<&Identifier> for frost_core::Identifier<C> {
    type Error = Error;

    fn try_from(s: &Identifier) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme == s.scheme {
            let bytes: <<C::Group as frost_core::Group>::Field as frost_core::Field>::Serialization =
                s.id.clone()
                    .try_into()
                    .map_err(|_| Error::General("Invalid identifier length".to_string()))?;
            let id = frost_core::Identifier::deserialize(&bytes)
                .map_err(|_| Error::General("Invalid identifier".to_string()))?;
            Ok(id)
        } else {
            Err(Error::General("Ciphersuite mismatch".to_string()))
        }
    }
}

impl Serialize for Identifier {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            (self.scheme.to_string(), self.id.clone()).serialize(s)
        } else {
            (self.scheme as u8, self.id.clone()).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (scheme, id) = if d.is_human_readable() {
            let (ty, id) = <(String, Vec<u8>)>::deserialize(d)?;
            let scheme: Scheme = ty
                .parse()
                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
            (scheme, id)
        } else {
            let (ty, id) = <(u8, Vec<u8>)>::deserialize(d)?;
            (
                ty.try_into()
                    .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?,
                id,
            )
        };
        Ok(Self { scheme, id })
    }
}

from_bytes_impl!(Identifier);

impl TryFrom<Identifier> for u128 {
    type Error = Error;

    fn try_from(id: Identifier) -> Result<Self, Self::Error> {
        let scalar_len = id.scheme.scalar_len().expect("Invalid ciphersuite");
        if id.id.len() != scalar_len {
            return Err(Error::General("Invalid identifier".to_string()));
        }
        let mut bytes = [0u8; 16];
        let result = match id.scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                if !bool::from(is_zero(&id.id[..scalar_len - 16])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u128".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[scalar_len - 16..]);
                u128::from_be_bytes(bytes)
            }
            ByteOrder::LittleEndian => {
                if !bool::from(is_zero(&id.id[16..])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u128".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[..16]);
                u128::from_le_bytes(bytes)
            }
        };
        Ok(result)
    }
}

impl TryFrom<Identifier> for u64 {
    type Error = Error;

    fn try_from(id: Identifier) -> Result<Self, Self::Error> {
        let scalar_len = id.scheme.scalar_len().expect("Invalid ciphersuite");
        if id.id.len() != scalar_len {
            return Err(Error::General("Invalid identifier".to_string()));
        }
        let mut bytes = [0u8; 8];
        let result = match id.scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                if !bool::from(is_zero(&id.id[..scalar_len - 8])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u64".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[scalar_len - 8..]);
                u64::from_be_bytes(bytes)
            }
            ByteOrder::LittleEndian => {
                if !bool::from(is_zero(&id.id[8..])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u64".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[..8]);
                u64::from_le_bytes(bytes)
            }
        };
        Ok(result)
    }
}

impl TryFrom<Identifier> for u32 {
    type Error = Error;

    fn try_from(id: Identifier) -> Result<Self, Self::Error> {
        let scalar_len = id.scheme.scalar_len().expect("Invalid ciphersuite");
        if id.id.len() != scalar_len {
            return Err(Error::General("Invalid identifier".to_string()));
        }
        let mut bytes = [0u8; 4];
        let result = match id.scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                if !bool::from(is_zero(&id.id[..scalar_len - 4])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u32".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[scalar_len - 4..]);
                u32::from_be_bytes(bytes)
            }
            ByteOrder::LittleEndian => {
                if !bool::from(is_zero(&id.id[4..])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u32".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[..4]);
                u32::from_le_bytes(bytes)
            }
        };
        Ok(result)
    }
}

impl TryFrom<Identifier> for u16 {
    type Error = Error;

    fn try_from(id: Identifier) -> Result<Self, Self::Error> {
        let scalar_len = id.scheme.scalar_len().expect("Invalid ciphersuite");
        if id.id.len() != scalar_len {
            return Err(Error::General("Invalid identifier".to_string()));
        }
        let mut bytes = [0u8; 2];
        let result = match id.scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                if !bool::from(is_zero(&id.id[..scalar_len - 2])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u16".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[scalar_len - 2..]);
                u16::from_be_bytes(bytes)
            }
            ByteOrder::LittleEndian => {
                if !bool::from(is_zero(&id.id[2..])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u16".to_string(),
                    ));
                }
                bytes.copy_from_slice(&id.id[..2]);
                u16::from_le_bytes(bytes)
            }
        };
        Ok(result)
    }
}

impl TryFrom<Identifier> for u8 {
    type Error = Error;

    fn try_from(id: Identifier) -> Result<Self, Self::Error> {
        let scalar_len = id.scheme.scalar_len().expect("Invalid ciphersuite");
        if id.id.len() != scalar_len {
            return Err(Error::General("Invalid identifier".to_string()));
        }
        let res = match id.scheme.byte_order().expect("Invalid ciphersuite") {
            ByteOrder::BigEndian => {
                if !bool::from(is_zero(&id.id[..scalar_len - 1])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u8".to_string(),
                    ));
                }
                id.id[scalar_len - 1]
            }
            ByteOrder::LittleEndian => {
                if !bool::from(is_zero(&id.id[1..])) {
                    return Err(Error::General(
                        "Invalid identifier, won't fit into u8".to_string(),
                    ));
                }
                id.id[0]
            }
        };
        Ok(res)
    }
}

impl Identifier {
    /// Determine if this identifier is invalid.
    pub fn is_zero(&self) -> subtle::Choice {
        let mut i = 0;
        for b in &self.id {
            i |= *b as i8;
        }
        let res = ((i | -i) >> 7) + 1;
        subtle::Choice::from(res as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;
    use rstest::*;

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519Sha512, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448Shake256, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::Ristretto255Sha512, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1Sha256, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256Sha256, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384Sha384, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubBlake2b512, Scheme::RedJubjubBlake2b512)]
    #[case::redpallas(frost_redpallas::PallasBlake2b512, Scheme::RedPallasBlake2b512)]
    #[case::taproot(frost_taproot::Secp256K1Taproot, Scheme::K256Taproot)]
    #[case::decaf377(frost_decaf377::Decaf377Blake2b512, Scheme::RedDecaf377Blake2b512)]
    fn convert<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        let id = Identifier::from((scheme, 1u8));
        let frost_id = frost_core::Identifier::<C>::try_from(&id).unwrap();
        assert_eq!(id, Identifier::from(frost_id));
    }

    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512)]
    #[case::ed448(Scheme::Ed448Shake256)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512)]
    #[case::k256(Scheme::K256Sha256)]
    #[case::p256(Scheme::P256Sha256)]
    #[case::p384(Scheme::P384Sha384)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512)]
    #[case::redpallas(Scheme::RedPallasBlake2b512)]
    #[case::taproot(Scheme::K256Taproot)]
    #[case::decaf377(Scheme::RedDecaf377Blake2b512)]
    fn serialize(#[case] scheme: Scheme) {
        const ITER: usize = 25;
        let scalar_len = scheme.scalar_len().unwrap();
        let mut id = vec![0u8; scalar_len];
        for _ in 0..ITER {
            rand::rngs::OsRng.fill_bytes(&mut id);
            let id = Identifier {
                scheme,
                id: id.clone(),
            };
            let res = serde_json::to_string(&id);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: Identifier = res.unwrap();
            assert_eq!(id, deserialized);
            let res = serde_bare::to_vec(&id);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scalar_len + 2);
            let res = serde_bare::from_slice(&serialized);
            assert!(res.is_ok());
            let deserialized: Identifier = res.unwrap();
            assert_eq!(id, deserialized);
        }
    }
}
