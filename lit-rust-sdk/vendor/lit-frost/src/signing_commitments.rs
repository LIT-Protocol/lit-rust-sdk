use crate::{Error, Scheme};
use frost_core::Ciphersuite;

const MAX_SIGNING_COMMITMENT_LEN: usize = 120;

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched using Scheme::pregenerate_signing_nonces.
/// Each [`SigningCommitments`] can be used for exactly one signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct SigningCommitments {
    /// The ciphersuite used for this signing commitment.
    pub scheme: Scheme,
    /// The serialized signing commitment.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: frost_core::round1::SigningCommitments<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: &frost_core::round1::SigningCommitments<C>) -> Self {
        let scheme = C::ID.parse().expect("Unknown ciphersuite");
        Self {
            scheme,
            value: s.serialize().expect("Error serializing signing commitment"),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningCommitments> for frost_core::round1::SigningCommitments<C> {
    type Error = Error;

    fn try_from(value: &SigningCommitments) -> Result<Self, Self::Error> {
        if value.scheme != C::ID.parse().expect("Unknown ciphersuite") {
            return Err(Error::General(
                "Signing commitment scheme does not match ciphersuite".to_string(),
            ));
        }
        frost_core::round1::SigningCommitments::<C>::deserialize(value.value.as_slice())
            .map_err(|_| Error::General("Error deserializing signing commitment".to_string()))
    }
}

from_bytes_impl!(SigningCommitments);
serde_impl!(
    SigningCommitments,
    commitment_len,
    MAX_SIGNING_COMMITMENT_LEN
);
display_impl!(SigningCommitments);

impl SigningCommitments {
    is_identity_impl!();
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

            let nonces = frost_core::round1::SigningNonces::<C>::new(&frost_share, &mut rng);
            let frost_commitments = frost_core::round1::SigningCommitments::<C>::from(&nonces);

            let commitments = SigningCommitments::from(&frost_commitments);
            let res = frost_core::round1::SigningCommitments::<C>::try_from(&commitments);
            assert!(res.is_ok());
            assert_eq!(frost_commitments, res.unwrap());
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

            let nonces = frost_core::round1::SigningNonces::<C>::new(&frost_share, &mut rng);
            let frost_commitments = frost_core::round1::SigningCommitments::<C>::from(&nonces);

            let commitments = SigningCommitments::from(&frost_commitments);

            let res = serde_json::to_string(&commitments);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: SigningCommitments = res.unwrap();
            assert_eq!(commitments, deserialized);
            let res = serde_bare::to_vec(&commitments);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.commitment_len().unwrap() + 1);
            let res = serde_bare::from_slice(&serialized);
            if res.is_err() {
                println!("Error: {:?}", res);
            }
            assert!(res.is_ok());
            let deserialized: SigningCommitments = res.unwrap();
            assert_eq!(commitments, deserialized);
        }
    }
}
