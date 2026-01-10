mod compatibility;

use crate::{Error, Scheme};
use frost_core::Ciphersuite;

const MAX_SIGNATURE_LEN: usize = 115;

/// A Schnorr signature
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct Signature {
    /// The signature scheme
    pub scheme: Scheme,
    /// The signature value
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::Signature<C>> for Signature {
    fn from(s: frost_core::Signature<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Signature<C>> for Signature {
    fn from(s: &frost_core::Signature<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&Signature> for frost_core::Signature<C> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let mut value = value.value.clone();
        match scheme {
            Scheme::SchnorrkelSubstrate => {
                // Unmark for schnorrkel
                let len = value.len() - 1;
                value[len] &= !128;
            }
            Scheme::K256Taproot => {
                if value.len() == 64 {
                    value.insert(0, 0x02);
                }
            }
            _ => {}
        }
        let bytes: C::SignatureSerialization = value
            .try_into()
            .map_err(|_| Error::General("Invalid signature length".to_string()))?;
        frost_core::Signature::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature".to_string()))
    }
}

from_bytes_impl!(Signature);
serde_impl!(Signature, signature_len, MAX_SIGNATURE_LEN);
display_impl!(Signature);

impl Signature {
    ct_is_zero_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::{Field, Group};
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
    #[case::schnorrkel(
        frost_schnorrkel25519::Schnorrkel25519Merlin,
        Scheme::SchnorrkelSubstrate
    )]
    fn convert<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let pt = C::Group::generator()
                * <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let share = <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let mut value = C::Group::serialize(&pt).as_ref().to_vec();
            value.extend_from_slice(
                <<<C as Ciphersuite>::Group as Group>::Field as Field>::serialize(&share).as_ref(),
            );
            let share = Signature { scheme, value };
            let frost_share = frost_core::Signature::<C>::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, Signature::from(&frost_share));
        }
    }

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
    #[case::schnorrkel(
        frost_schnorrkel25519::Schnorrkel25519Merlin,
        Scheme::SchnorrkelSubstrate
    )]
    fn serialize<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let pt = C::Group::generator()
                * <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let share = <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let mut value = C::Group::serialize(&pt).as_ref().to_vec();
            value.extend_from_slice(
                <<<C as Ciphersuite>::Group as Group>::Field as Field>::serialize(&share).as_ref(),
            );
            let share = Signature { scheme, value };
            let res = serde_json::to_string(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: Signature = res.unwrap();
            assert_eq!(share, deserialized);
            let res = serde_bare::to_vec(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.signature_len().unwrap() + 1);
            let res = serde_bare::from_slice(&serialized);
            if res.is_err() {
                println!("Error: {:?}", res);
            }
            assert!(res.is_ok());
            let deserialized: Signature = res.unwrap();
            assert_eq!(share, deserialized);
        }
    }
}
