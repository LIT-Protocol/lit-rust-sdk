use super::*;
use lit_rust_crypto::*;

impl From<ed25519_dalek::Signature> for Signature {
    fn from(s: ed25519_dalek::Signature) -> Self {
        Self::from(&s)
    }
}

impl From<&ed25519_dalek::Signature> for Signature {
    fn from(s: &ed25519_dalek::Signature) -> Self {
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<&Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::Ed25519Sha512;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes: ed25519_dalek::ed25519::SignatureBytes = value
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        Ok(ed25519_dalek::Signature::from_bytes(&bytes))
    }
}

impl TryFrom<Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl From<reddsa::Signature<reddsa::sapling::SpendAuth>> for Signature {
    fn from(s: reddsa::Signature<reddsa::sapling::SpendAuth>) -> Self {
        let bytes: [u8; 64] = s.into();
        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: bytes.to_vec(),
        }
    }
}

impl From<&reddsa::Signature<reddsa::sapling::SpendAuth>> for Signature {
    fn from(s: &reddsa::Signature<reddsa::sapling::SpendAuth>) -> Self {
        Self::from(*s)
    }
}

impl From<reddsa::Signature<reddsa::orchard::SpendAuth>> for Signature {
    fn from(s: reddsa::Signature<reddsa::orchard::SpendAuth>) -> Self {
        let bytes: [u8; 64] = s.into();
        Self {
            scheme: Scheme::RedPallasBlake2b512,
            value: bytes.to_vec(),
        }
    }
}

impl From<&reddsa::Signature<reddsa::orchard::SpendAuth>> for Signature {
    fn from(s: &reddsa::Signature<reddsa::orchard::SpendAuth>) -> Self {
        Self::from(*s)
    }
}

impl<S: reddsa::SigType> TryFrom<Signature> for reddsa::Signature<S> {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<S: reddsa::SigType> TryFrom<&Signature> for reddsa::Signature<S> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        if Scheme::RedPallasBlake2b512 != value.scheme
            && Scheme::RedJubjubBlake2b512 != value.scheme
        {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes: [u8; 64] = value
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        Ok(Self::from(bytes))
    }
}

impl<D: decaf377_rdsa::Domain> From<decaf377_rdsa::Signature<D>> for Signature {
    fn from(s: decaf377_rdsa::Signature<D>) -> Self {
        Self::from(&s)
    }
}

impl<D: decaf377_rdsa::Domain> From<&decaf377_rdsa::Signature<D>> for Signature {
    fn from(s: &decaf377_rdsa::Signature<D>) -> Self {
        let bytes: [u8; 64] = s.to_bytes();
        Self {
            scheme: Scheme::RedDecaf377Blake2b512,
            value: bytes.to_vec(),
        }
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<Signature> for decaf377_rdsa::Signature<D> {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<&Signature> for decaf377_rdsa::Signature<D> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::RedDecaf377Blake2b512;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes: [u8; 64] = value
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        Ok(Self::from(bytes))
    }
}

impl From<k256::schnorr::Signature> for Signature {
    fn from(s: k256::schnorr::Signature) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::schnorr::Signature> for Signature {
    fn from(s: &k256::schnorr::Signature) -> Self {
        Self {
            scheme: Scheme::K256Taproot,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<Signature> for k256::schnorr::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Signature> for k256::schnorr::Signature {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::K256Taproot;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        match value.value.len() {
            64 => k256::schnorr::Signature::try_from(value.value.as_slice())
                .map_err(|_| Error::General("Error converting signature from bytes".to_string())),
            65 => k256::schnorr::Signature::try_from(&value.value[1..])
                .map_err(|_| Error::General("Error converting signature from bytes".to_string())),
            _ => Err(Error::General("Invalid signature length".to_string())),
        }
    }
}

impl From<schnorrkel::Signature> for Signature {
    fn from(s: schnorrkel::Signature) -> Self {
        Self::from(&s)
    }
}

impl From<&schnorrkel::Signature> for Signature {
    fn from(s: &schnorrkel::Signature) -> Self {
        Self {
            scheme: Scheme::SchnorrkelSubstrate,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<Signature> for schnorrkel::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Signature> for schnorrkel::Signature {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::SchnorrkelSubstrate;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        // schnorrkel require the last byte be marked
        let mut bytes = value.value.clone();
        bytes[value.value.len() - 1] |= 128;
        schnorrkel::Signature::from_bytes(&bytes)
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use rand::Rng;
    use sha2::{Digest, Sha256};
    use signature_crypto::hazmat::PrehashVerifier;
    use std::num::NonZeroU16;

    #[test]
    fn ed25519_signature_conversion_simple() {
        use ed25519_dalek::Signer;

        let mut rng = rand::thread_rng();
        let sk = rng.r#gen::<ed25519_dalek::SecretKey>();
        let sk = ed25519_dalek::SigningKey::from(sk);
        let msg = b"Hello, world!";
        let sig = sk.sign(msg);
        let sig2 = Signature::from(&sig);
        let sig3 = ed25519_dalek::Signature::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn ed25519_signature_frost_verify() {
        use ed25519_dalek::Verifier;
        const SCHEME: Scheme = Scheme::Ed25519Sha512;
        const MSG: &[u8] = b"ed25519_signature_frost_verify";

        let mut rng = rand::thread_rng();

        let (secret_shares, verifying_key) =
            SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = SCHEME.signing_round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id, (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = SCHEME.signing_round2(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(2).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
        }

        let res = SCHEME.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        let signature = res.unwrap();
        assert!(SCHEME.verify(MSG, &verifying_key, &signature).is_ok());

        // Convert to concrete types and see if verify works
        let signature = ed25519_dalek::Signature::try_from(signature).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            verifying_key.value.as_slice().try_into().unwrap(),
        )
        .unwrap();
        assert!(verifying_key.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn redjubjub_signature_conversion_simple() {
        const MSG: &[u8] = b"redjubjub_signature_conversion_simple";
        let mut rng = rand_core::OsRng;
        let sk = reddsa::SigningKey::<reddsa::sapling::SpendAuth>::new(&mut rng);
        let sig = sk.sign(&mut rng, MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = reddsa::Signature::<reddsa::sapling::SpendAuth>::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);

        let sk = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
        let sig = sk.sign(&mut rng, MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = reddsa::Signature::<reddsa::orchard::SpendAuth>::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn redjubjub_signature_frost_verify() {
        const SCHEME: Scheme = Scheme::RedJubjubBlake2b512;
        const MSG: &[u8] = b"redjubjub_signature_frost_verify";

        let mut rng = rand_core::OsRng;

        let (secret_shares, verifying_key) =
            SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = SCHEME.signing_round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id, (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = SCHEME.signing_round2(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(2).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
        }

        let res = SCHEME.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        let signature = res.unwrap();
        assert!(SCHEME.verify(MSG, &verifying_key, &signature).is_ok());

        // Convert to concrete types and see if verify works
        let signature =
            reddsa::Signature::<reddsa::sapling::SpendAuth>::try_from(signature).unwrap();
        let verifying_key = reddsa::VerificationKey::try_from(verifying_key).unwrap();
        assert!(verifying_key.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn taproot_signature_conversion_simple() {
        use signature_crypto::Signer;

        const MSG: &[u8] = b"k256_signature_conversion_simple";
        let mut rng = rand_core::OsRng;
        let sk = k256::schnorr::SigningKey::random(&mut rng);
        let sig = sk.sign(MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = k256::schnorr::Signature::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn taproot_signature_frost_verify() {
        const SCHEME: Scheme = Scheme::K256Taproot;
        const MSG: &[u8] = b"secp256k1_taproot_signature_frost_verify";

        let msg = Sha256::default().chain_update(MSG).finalize();

        let mut rng = rand_core::OsRng;

        let (secret_shares, verifying_key) =
            SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        let vk = k256::schnorr::VerifyingKey::try_from(&verifying_key).unwrap();

        for _ in 0..30 {
            let mut signing_package = BTreeMap::new();
            let mut signing_commitments = Vec::new();

            for (id, secret_share) in &secret_shares {
                let res = SCHEME.signing_round1(&secret_share, &mut rng);
                assert!(res.is_ok());
                let (nonces, commitments) = res.unwrap();
                signing_package.insert(id.clone(), (nonces, secret_share));
                signing_commitments.push((id.clone(), commitments));
            }

            let mut verifying_shares = Vec::new();
            let mut signature_shares = Vec::new();
            for (id, (nonces, secret_share)) in signing_package {
                let res = SCHEME.signing_round2(
                    MSG,
                    &signing_commitments[..],
                    &nonces,
                    &KeyPackage {
                        identifier: id.clone(),
                        secret_share: secret_share.clone(),
                        verifying_key: verifying_key.clone(),
                        threshold: NonZeroU16::new(2).unwrap(),
                    },
                );
                let signature = res.unwrap();
                signature_shares.push((id.clone(), signature));
                verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
            }

            let res = SCHEME.aggregate(
                MSG,
                &signing_commitments,
                &signature_shares,
                &verifying_shares,
                &verifying_key,
            );
            let signature = res.unwrap();
            // Convert to concrete types and see if verify works
            let sig = k256::schnorr::Signature::try_from(&signature).unwrap();
            assert!(vk.verify_prehash(&msg[..], &sig).is_ok());
        }
    }
}
