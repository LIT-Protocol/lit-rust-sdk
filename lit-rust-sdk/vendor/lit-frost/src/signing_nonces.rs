use crate::{Error, Scheme};
use frost_core::Ciphersuite;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
};
use std::fmt::{self, Display, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Comprised of hiding and binding nonces
///
/// Note that [`SigningNonces`] must be used only once for a signing operation;
/// re-using nonces will result in leakage of a signer’s long-lived signing key.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct SigningNonces {
    /// The ciphersuite used for the signing nonces
    pub scheme: Scheme,
    /// The hiding nonce
    pub hiding: Vec<u8>,
    /// The binding nonce
    pub binding: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: frost_core::round1::SigningNonces<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: &frost_core::round1::SigningNonces<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            hiding: s.hiding().serialize().as_ref().to_vec(),
            binding: s.binding().serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningNonces> for frost_core::round1::SigningNonces<C> {
    type Error = Error;

    fn try_from(value: &SigningNonces) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signing nonces".to_string(),
            ));
        }
        let hiding_bytes: <<C::Group as frost_core::Group>::Field as frost_core::Field>::Serialization =
            value.hiding.clone()
                .try_into()
                .map_err(|_| Error::General("Invalid hiding nonce length".to_string()))?;
        let hiding = frost_core::round1::Nonce::<C>::deserialize(hiding_bytes)
            .map_err(|_| Error::General("Error deserializing hiding nonce".to_string()))?;
        let binding_bytes: <<C::Group as frost_core::Group>::Field as frost_core::Field>::Serialization =
            value.binding.clone()
                .try_into()
                .map_err(|_| Error::General("Invalid binding nonce length".to_string()))?;
        let binding = frost_core::round1::Nonce::<C>::deserialize(binding_bytes)
            .map_err(|_| Error::General("Error deserializing binding nonce".to_string()))?;
        let signing_nonces = frost_core::round1::SigningNonces::<C>::from_nonces(hiding, binding);
        Ok(signing_nonces)
    }
}

impl Serialize for SigningNonces {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            (
                self.scheme.to_string(),
                hex::encode(&self.hiding),
                hex::encode(&self.binding),
            )
                .serialize(s)
        } else {
            let mut seq = s.serialize_tuple(1 + self.hiding.len() + self.binding.len())?;
            seq.serialize_element(&(self.scheme as u8))?;
            for byte in &self.hiding {
                seq.serialize_element(byte)?;
            }
            for byte in &self.binding {
                seq.serialize_element(byte)?;
            }

            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for SigningNonces {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let (ty, hiding, binding) = <(String, String, String)>::deserialize(d)?;
            let scheme: Scheme = ty
                .parse()
                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
            let hiding = hex::decode(hiding)
                .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
            let binding = hex::decode(binding)
                .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
            Ok(Self {
                scheme,
                hiding,
                binding,
            })
        } else {
            struct SigningNoncesVisitor;

            impl<'de> Visitor<'de> for SigningNoncesVisitor {
                type Value = SigningNonces;

                fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a byte sequence")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let scheme = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::custom("Missing scheme"))?;
                    let scheme = Scheme::try_from(scheme)
                        .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
                    let length = scheme
                        .scalar_len()
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?;
                    let mut hiding = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        hiding.push(b);
                        if hiding.len() == length {
                            break;
                        }
                    }
                    if hiding.len() != length {
                        return Err(serde::de::Error::custom("Invalid hiding length"));
                    }
                    let mut binding = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        binding.push(b);
                        if binding.len() == length {
                            break;
                        }
                    }
                    if binding.len() != length {
                        return Err(serde::de::Error::custom("Invalid binding length"));
                    }
                    Ok(SigningNonces {
                        scheme,
                        hiding,
                        binding,
                    })
                }
            }

            d.deserialize_tuple(115, SigningNoncesVisitor)
        }
    }
}

impl Display for SigningNonces {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scheme: {}, hiding: 0x{}, binding: 0x{}",
            self.scheme,
            hex::encode(&self.hiding),
            hex::encode(&self.binding)
        )
    }
}

from_bytes_impl!(SigningNonces);

impl Zeroize for SigningNonces {
    fn zeroize(&mut self) {
        self.hiding.zeroize();
        self.binding.zeroize();
    }
}

impl ZeroizeOnDrop for SigningNonces {}

impl SigningNonces {
    /// Return true if the nonces are valid aka not zero
    pub fn is_zero(&self) -> subtle::Choice {
        crate::is_zero(&self.hiding) | crate::is_zero(&self.binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningShare;
    use frost_core::Field;
    use rstest::*;

    #[rstest]
    #[case::ed25519(
        frost_ed25519::Ed25519Sha512,
        frost_ed25519::Ed25519ScalarField,
        Scheme::Ed25519Sha512
    )]
    #[case::ed448(
        frost_ed448::Ed448Shake256,
        frost_ed448::Ed448ScalarField,
        Scheme::Ed448Shake256
    )]
    #[case::ristretto25519(
        frost_ristretto255::Ristretto255Sha512,
        frost_ristretto255::RistrettoScalarField,
        Scheme::Ristretto25519Sha512
    )]
    #[case::k256(
        frost_secp256k1::Secp256K1Sha256,
        frost_secp256k1::Secp256K1ScalarField,
        Scheme::K256Sha256
    )]
    #[case::p256(
        frost_p256::P256Sha256,
        frost_p256::P256ScalarField,
        Scheme::P256Sha256
    )]
    #[case::p384(
        frost_p384::P384Sha384,
        frost_p384::P384ScalarField,
        Scheme::P384Sha384
    )]
    #[case::redjubjub(
        frost_redjubjub::JubjubBlake2b512,
        frost_redjubjub::JubjubScalarField,
        Scheme::RedJubjubBlake2b512
    )]
    #[case::redpallas(
        frost_redpallas::PallasBlake2b512,
        frost_redpallas::PallasScalarField,
        Scheme::RedPallasBlake2b512
    )]
    #[case::taproot(
        frost_taproot::Secp256K1Taproot,
        frost_taproot::Secp256K1TaprootScalarField,
        Scheme::K256Taproot
    )]
    #[case::decaf377(
        frost_decaf377::Decaf377Blake2b512,
        frost_decaf377::Decaf377ScalarField,
        Scheme::RedDecaf377Blake2b512
    )]
    fn convert<C: Ciphersuite, F: Field>(#[case] _c: C, #[case] _f: F, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = F::random(&mut rng);
            let share = SigningShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let frost_share = frost_core::keys::SigningShare::<C>::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();

            let frost_nonces = frost_core::round1::SigningNonces::<C>::new(&frost_share, &mut rng);

            let nonces = SigningNonces::from(&frost_nonces);
            let res = frost_core::round1::SigningNonces::<C>::try_from(&nonces);
            assert!(res.is_ok());
            assert_eq!(nonces, SigningNonces::from(res.unwrap()));
        }
    }

    #[rstest]
    #[case::ed25519(
        frost_ed25519::Ed25519Sha512,
        frost_ed25519::Ed25519ScalarField,
        Scheme::Ed25519Sha512
    )]
    #[case::ed448(
        frost_ed448::Ed448Shake256,
        frost_ed448::Ed448ScalarField,
        Scheme::Ed448Shake256
    )]
    #[case::ristretto25519(
        frost_ristretto255::Ristretto255Sha512,
        frost_ristretto255::RistrettoScalarField,
        Scheme::Ristretto25519Sha512
    )]
    #[case::k256(
        frost_secp256k1::Secp256K1Sha256,
        frost_secp256k1::Secp256K1ScalarField,
        Scheme::K256Sha256
    )]
    #[case::p256(
        frost_p256::P256Sha256,
        frost_p256::P256ScalarField,
        Scheme::P256Sha256
    )]
    #[case::p384(
        frost_p384::P384Sha384,
        frost_p384::P384ScalarField,
        Scheme::P384Sha384
    )]
    #[case::redjubjub(
        frost_redjubjub::JubjubBlake2b512,
        frost_redjubjub::JubjubScalarField,
        Scheme::RedJubjubBlake2b512
    )]
    #[case::redpallas(
        frost_redpallas::PallasBlake2b512,
        frost_redpallas::PallasScalarField,
        Scheme::RedPallasBlake2b512
    )]
    #[case::taproot(
        frost_taproot::Secp256K1Taproot,
        frost_taproot::Secp256K1TaprootScalarField,
        Scheme::K256Taproot
    )]
    #[case::decaf377(
        frost_decaf377::Decaf377Blake2b512,
        frost_decaf377::Decaf377ScalarField,
        Scheme::RedDecaf377Blake2b512
    )]
    fn serialize<C: Ciphersuite, F: Field>(#[case] _c: C, #[case] _f: F, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = F::random(&mut rng);
            let share = SigningShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };

            let res = frost_core::keys::SigningShare::<C>::try_from(&share);
            assert!(res.is_ok());
            let frost_share = res.unwrap();

            let frost_nonces = frost_core::round1::SigningNonces::<C>::new(&frost_share, &mut rng);

            let nonces = SigningNonces::from(&frost_nonces);

            let res = serde_json::to_string(&nonces);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: SigningNonces = res.unwrap();
            assert_eq!(nonces, deserialized);
            let res = serde_bare::to_vec(&nonces);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.scalar_len().unwrap() * 2 + 1);
            let res = serde_bare::from_slice(&serialized);
            if res.is_err() {
                println!("Error: {:?}", res);
            }
            assert!(res.is_ok());
            let deserialized: SigningNonces = res.unwrap();
            assert_eq!(nonces, deserialized);
        }
    }
}
