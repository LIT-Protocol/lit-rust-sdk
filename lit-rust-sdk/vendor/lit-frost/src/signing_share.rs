mod compatibility;

use crate::{Error, Scheme};
use frost_core::Ciphersuite;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_SIGNING_SHARE_LEN: usize = 58;

/// A secret scalar value representing a signer’s share of the group secret.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct SigningShare {
    /// The scheme used to generate the signing share.
    pub scheme: Scheme,
    /// The value of the signing share.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: frost_core::keys::SigningShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: &frost_core::keys::SigningShare<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningShare> for frost_core::keys::SigningShare<C> {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        if value.scheme != C::ID.parse().expect("Unknown ciphersuite") {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes: <<C::Group as frost_core::Group>::Field as frost_core::Field>::Serialization =
            value
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::General("Invalid signing share length".to_string()))?;
        frost_core::keys::SigningShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error converting signing share".to_string()))
    }
}

from_bytes_impl!(SigningShare);
serde_impl!(SigningShare, scalar_len, MAX_SIGNING_SHARE_LEN);
display_impl!(SigningShare);

impl Zeroize for SigningShare {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl ZeroizeOnDrop for SigningShare {}

impl SigningShare {
    ct_is_zero_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::Field;
    use lit_rust_crypto::*;
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
        frost_secp256k1::Secp256K1ScalarField,
        Scheme::K256Taproot
    )]
    #[case::decaf377(
        frost_decaf377::Decaf377Blake2b512,
        frost_decaf377::Decaf377ScalarField,
        Scheme::RedDecaf377Blake2b512
    )]
    fn convert_1<C: Ciphersuite, F: Field>(#[case] _c: C, #[case] _f: F, #[case] scheme: Scheme) {
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
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_k256() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = k256::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::K256Sha256, share).try_into().unwrap();
            let frost_share = k256::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::K256Sha256, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_p256() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = p256::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::P256Sha256, share).try_into().unwrap();
            let frost_share = p256::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::P256Sha256, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_p384() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = p384::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::P384Sha384, share).try_into().unwrap();
            let frost_share = p384::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::P384Sha384, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_ed25519_ristretto25519() {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = curve25519_dalek::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::Ed25519Sha512, share).try_into().unwrap();
            let frost_share = curve25519_dalek::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::Ed25519Sha512, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_ed448() {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = ed448_goldilocks::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::Ed448Shake256, share).try_into().unwrap();
            let frost_share = ed448_goldilocks::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::Ed448Shake256, &frost_share));
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_redjubjub() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = jubjub::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::RedJubjubBlake2b512, share).try_into().unwrap();
            let frost_share = jubjub::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::RedJubjubBlake2b512, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_redpallas() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = pallas::Scalar::random(&mut rng);
            let share: SigningShare = (Scheme::RedPallasBlake2b512, share).try_into().unwrap();
            let frost_share = pallas::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::RedPallasBlake2b512, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[test]
    fn convert_vsss_wrapped() {
        use vsss_rs::elliptic_curve::Field;
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = curve25519::WrappedScalar::random(&mut rng);
            let share: SigningShare = (Scheme::Ed25519Sha512, share).try_into().unwrap();
            let frost_share = curve25519::WrappedScalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            let res = SigningShare::try_from((Scheme::Ed25519Sha512, &frost_share));
            assert!(res.is_ok());
            assert_eq!(share, res.unwrap());
        }
    }

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519ScalarField, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448ScalarField, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::RistrettoScalarField, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1ScalarField, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256ScalarField, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384ScalarField, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubScalarField, Scheme::RedJubjubBlake2b512)]
    #[case::redpallas(frost_redpallas::PallasScalarField, Scheme::RedPallasBlake2b512)]
    #[case::taproot(frost_taproot::Secp256K1TaprootScalarField, Scheme::K256Taproot)]
    #[case::decaf377(frost_decaf377::Decaf377ScalarField, Scheme::RedDecaf377Blake2b512)]
    fn serialize<F: Field>(#[case] _f: F, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = F::random(&mut rng);
            let share = SigningShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let res = serde_json::to_string(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: SigningShare = res.unwrap();
            assert_eq!(share, deserialized);
            let res = serde_bare::to_vec(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.scalar_len().unwrap() + 1);
            let res = serde_bare::from_slice(&serialized);
            if res.is_err() {
                println!("Error: {:?}", res);
            }
            assert!(res.is_ok());
            let deserialized: SigningShare = res.unwrap();
            assert_eq!(share, deserialized);
        }
    }
}
