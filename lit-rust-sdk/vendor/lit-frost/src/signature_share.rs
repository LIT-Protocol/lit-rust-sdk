use crate::{Error, Scheme};
use frost_core::Ciphersuite;

const MAX_SIGNATURE_SHARE_LEN: usize = 58;

/// A participant’s signature share, which is aggregated with all other signer’s shares into the joint signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct SignatureShare {
    /// The ciphersuite used to create this signature share.
    pub scheme: Scheme,
    /// The signature share value.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: frost_core::round2::SignatureShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: &frost_core::round2::SignatureShare<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SignatureShare> for frost_core::round2::SignatureShare<C> {
    type Error = Error;

    fn try_from(value: &SignatureShare) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature share".to_string(),
            ));
        }
        let bytes: <<C::Group as frost_core::Group>::Field as frost_core::Field>::Serialization =
            value
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::General("Invalid signature share length".to_string()))?;
        frost_core::round2::SignatureShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature share".to_string()))
    }
}

from_bytes_impl!(SignatureShare);
serde_impl!(SignatureShare, scalar_len, MAX_SIGNATURE_SHARE_LEN);
display_impl!(SignatureShare);

impl SignatureShare {
    ct_is_zero_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let share = SignatureShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let frost_share = frost_core::round2::SignatureShare::<C>::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SignatureShare::from(&frost_share));
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
            let share = SignatureShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let res = serde_json::to_string(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: SignatureShare = res.unwrap();
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
            let deserialized: SignatureShare = res.unwrap();
            assert_eq!(share, deserialized);
        }
    }
}
