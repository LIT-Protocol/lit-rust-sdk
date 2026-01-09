use crate::{Error, Scheme};
use frost_core::Ciphersuite;

const MAX_VERIFYING_SHARE_LEN: usize = 58;

/// A public group element that represents a single signer’s public verification share.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct VerifyingShare {
    /// The scheme associated with this share.
    pub scheme: Scheme,
    /// The share value.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::keys::VerifyingShare<C>> for VerifyingShare {
    fn from(s: frost_core::keys::VerifyingShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::VerifyingShare<C>> for VerifyingShare {
    fn from(s: &frost_core::keys::VerifyingShare<C>) -> Self {
        let value = s.serialize().as_ref().to_vec();
        let scheme = C::ID.parse::<Scheme>().expect("Unknown ciphersuite");
        Self { scheme, value }
    }
}

impl<C: Ciphersuite> TryFrom<&VerifyingShare> for frost_core::keys::VerifyingShare<C> {
    type Error = Error;

    fn try_from(value: &VerifyingShare) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match verifying share".to_string(),
            ));
        }
        // let bytes =
        //     <C::Group as Group>::Serialization::try_from(value.value.to_vec()).map_err(|_| {
        //         Error::General("Error converting verifying share from bytes".to_string())
        //     })?;
        let bytes: <C::Group as frost_core::Group>::Serialization = value
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::General("Invalid verifying share length".to_string()))?;
        frost_core::keys::VerifyingShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing verifying share".to_string()))
    }
}

from_bytes_impl!(VerifyingShare);
serde_impl!(
    VerifyingShare,
    compressed_point_len,
    MAX_VERIFYING_SHARE_LEN
);
display_impl!(VerifyingShare);

impl VerifyingShare {
    is_identity_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::Group;
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
        let value = frost_core::keys::VerifyingShare::<C>::new(C::Group::generator());
        let vk = VerifyingShare::from(&value);
        assert_eq!(vk.scheme, scheme);
        assert_eq!(vk.value.len(), scheme.compressed_point_len().unwrap());
        let res = frost_core::keys::VerifyingShare::<C>::try_from(&vk);
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
            let vk = frost_core::keys::VerifyingShare::<C>::new(pt);
            let vk2 = VerifyingShare::from(&vk);
            assert_eq!(vk2.scheme, scheme);
            assert_eq!(vk2.value.len(), scheme.compressed_point_len().unwrap());
            let res = serde_json::to_string(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str::<VerifyingShare>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);

            let res = serde_bare::to_vec(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.compressed_point_len().unwrap() + 1);
            let res = serde_bare::from_slice::<VerifyingShare>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);
        }
    }
}
