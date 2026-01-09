mod compatibility;

use crate::{Error, Scheme};
use frost_core::Ciphersuite;

const MAX_VERIFYING_KEY_LEN: usize = 58;

/// A valid verifying key for Schnorr signatures
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct VerifyingKey {
    /// The scheme used by this verifying key
    pub scheme: Scheme,
    /// The value of the verifying key
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: frost_core::VerifyingKey<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: &frost_core::VerifyingKey<C>) -> Self {
        let value = s.serialize().as_ref().to_vec();
        let scheme = C::ID.parse::<Scheme>().expect("Unknown ciphersuite");
        Self { scheme, value }
    }
}

impl<C: Ciphersuite> TryFrom<&VerifyingKey> for frost_core::VerifyingKey<C> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes: <C::Group as frost_core::Group>::Serialization = value
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::General("Invalid verifying key length".to_string()))?;
        frost_core::VerifyingKey::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing verifying key".to_string()))
    }
}

from_bytes_impl!(VerifyingKey);
serde_impl!(VerifyingKey, compressed_point_len, MAX_VERIFYING_KEY_LEN);
display_impl!(VerifyingKey);

impl VerifyingKey {
    is_identity_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost::Group;
    use frost_core as frost;
    use lit_rust_crypto::*;
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
    fn convert_1<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        let value = frost_core::VerifyingKey::<C>::new(C::Group::generator());
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, scheme);
        assert_eq!(vk.value.len(), scheme.compressed_point_len().unwrap());
        let res = frost::VerifyingKey::<C>::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);
    }

    #[test]
    fn convert_k256() {
        const SCHEME: Scheme = Scheme::K256Sha256;

        let value = k256::ProjectivePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = k256::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = k256::AffinePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = k256::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_p256() {
        const SCHEME: Scheme = Scheme::P256Sha256;

        let value = p256::ProjectivePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p256::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = p256::AffinePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p256::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_p384() {
        const SCHEME: Scheme = Scheme::P384Sha384;

        let value = p384::ProjectivePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p384::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = p384::AffinePoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p384::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ed25519() {
        const SCHEME: Scheme = Scheme::Ed25519Sha512;

        let value = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::EdwardsPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::edwards::CompressedEdwardsY::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ristretto25519() {
        const SCHEME: Scheme = Scheme::Ristretto25519Sha512;

        let value = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::RistrettoPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::ristretto::CompressedRistretto::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ed448() {
        const SCHEME: Scheme = Scheme::Ed448Shake256;

        let value = ed448_goldilocks::EdwardsPoint::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = ed448_goldilocks::EdwardsPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = ed448_goldilocks::CompressedEdwardsY::GENERATOR;
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = ed448_goldilocks::CompressedEdwardsY::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_redjubjub() {
        use group::{Group, cofactor::CofactorCurveAffine};

        const SCHEME: Scheme = Scheme::RedJubjubBlake2b512;

        let value = jubjub::ExtendedPoint::generator();
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::ExtendedPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = jubjub::AffinePoint::generator();
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::AffinePoint::try_from(&vk);
        assert!(res.is_ok());

        let value = jubjub::SubgroupPoint::generator();
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::SubgroupPoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_redpallas() {
        const SCHEME: Scheme = Scheme::RedPallasBlake2b512;

        let value = red_pallas_signing_generator();
        let res = VerifyingKey::try_from((SCHEME, &value));
        assert!(res.is_ok());
        let vk = res.unwrap();
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = pallas::Point::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);
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
    fn serialize<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        use frost_core::Field;

        const ITER: usize = 25;

        let mut rng = rand::rngs::OsRng;

        for _ in 0..ITER {
            let pt = C::Group::generator()
                * <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let vk = frost_core::VerifyingKey::<C>::new(pt);
            let vk2 = VerifyingKey::from(&vk);
            assert_eq!(vk2.scheme, scheme);
            assert_eq!(vk2.value.len(), scheme.compressed_point_len().unwrap());
            let res = serde_json::to_string(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str::<VerifyingKey>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);

            let res = serde_bare::to_vec(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.compressed_point_len().unwrap() + 1);
            let res = serde_bare::from_slice::<VerifyingKey>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);
        }
    }
}
