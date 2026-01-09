use super::*;
use lit_rust_crypto::*;

try_from_scheme_ref!(
    VerifyingKey,
    curve25519_dalek::edwards::CompressedEdwardsY,
    |scheme, s: &curve25519_dalek::edwards::CompressedEdwardsY| {
        if scheme != Scheme::Ed25519Sha512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    curve25519_dalek::edwards::CompressedEdwardsY,
    VerifyingKey,
    |value: &VerifyingKey| {
        if value.scheme != Scheme::Ed25519Sha512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    curve25519_dalek::edwards::EdwardsPoint,
    |scheme, s: &curve25519_dalek::edwards::EdwardsPoint| {
        if scheme != Scheme::Ed25519Sha512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.compress().as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    curve25519_dalek::edwards::EdwardsPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = curve25519_dalek::edwards::CompressedEdwardsY::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    curve25519_dalek::ristretto::CompressedRistretto,
    |scheme, s: &curve25519_dalek::ristretto::CompressedRistretto| {
        if scheme != Scheme::Ristretto25519Sha512 && scheme != Scheme::SchnorrkelSubstrate {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    curve25519_dalek::ristretto::CompressedRistretto,
    VerifyingKey,
    |value: &VerifyingKey| {
        if (value.scheme != Scheme::Ristretto25519Sha512
            && value.scheme != Scheme::SchnorrkelSubstrate)
            || value.value.len() != 32
        {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        curve25519_dalek::ristretto::CompressedRistretto::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    curve25519_dalek::ristretto::RistrettoPoint,
    |scheme, s: &curve25519_dalek::ristretto::RistrettoPoint| {
        if scheme != Scheme::Ristretto25519Sha512 && scheme != Scheme::SchnorrkelSubstrate {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.compress().as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    curve25519_dalek::ristretto::RistrettoPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = curve25519_dalek::ristretto::CompressedRistretto::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);

try_from_scheme_ref!(
    VerifyingKey,
    vsss_rs::curve25519_dalek::edwards::CompressedEdwardsY,
    |scheme, s: &vsss_rs::curve25519_dalek::edwards::CompressedEdwardsY| {
        if scheme != Scheme::Ed25519Sha512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::edwards::CompressedEdwardsY,
    VerifyingKey,
    |value: &VerifyingKey| {
        if value.scheme != Scheme::Ed25519Sha512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        vsss_rs::curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    vsss_rs::curve25519_dalek::edwards::EdwardsPoint,
    |scheme, s: &vsss_rs::curve25519_dalek::edwards::EdwardsPoint| {
        if scheme != Scheme::Ed25519Sha512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.compress().as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::edwards::EdwardsPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = vsss_rs::curve25519_dalek::edwards::CompressedEdwardsY::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    vsss_rs::curve25519_dalek::ristretto::CompressedRistretto,
    |scheme, s: &vsss_rs::curve25519_dalek::ristretto::CompressedRistretto| {
        if scheme != Scheme::Ristretto25519Sha512 && scheme != Scheme::SchnorrkelSubstrate {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::ristretto::CompressedRistretto,
    VerifyingKey,
    |value: &VerifyingKey| {
        if (value.scheme != Scheme::Ristretto25519Sha512
            && value.scheme != Scheme::SchnorrkelSubstrate)
            || value.value.len() != 32
        {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        vsss_rs::curve25519_dalek::ristretto::CompressedRistretto::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    vsss_rs::curve25519_dalek::ristretto::RistrettoPoint,
    |scheme, s: &vsss_rs::curve25519_dalek::ristretto::RistrettoPoint| {
        if scheme != Scheme::Ristretto25519Sha512 && scheme != Scheme::SchnorrkelSubstrate {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.compress().as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::ristretto::RistrettoPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = vsss_rs::curve25519_dalek::ristretto::CompressedRistretto::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    k256::ProjectivePoint,
    |scheme, s: &k256::ProjectivePoint| {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    k256::ProjectivePoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

        let scheme = value.scheme;
        if (scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot)
            || value.value.len() != 33
        {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt = EncodedPoint::<k256::Secp256k1>::from_bytes(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        Option::from(k256::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    k256::AffinePoint,
    |scheme, s: &k256::AffinePoint| {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(k256::AffinePoint, VerifyingKey, |value: &VerifyingKey| {
    use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

    let scheme = value.scheme;
    if (scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot) || value.value.len() != 33 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    let pt = EncodedPoint::<k256::Secp256k1>::from_bytes(&value.value)
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
    Option::from(k256::AffinePoint::from_encoded_point(&pt))
        .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
});
try_from_scheme_ref!(
    VerifyingKey,
    p256::ProjectivePoint,
    |scheme, s: &p256::ProjectivePoint| {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::P256Sha256 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    p256::ProjectivePoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

        let scheme = value.scheme;
        if scheme != Scheme::P256Sha256 || value.value.len() != 33 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt = EncodedPoint::<p256::NistP256>::from_bytes(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        Option::from(p256::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    p256::AffinePoint,
    |scheme, s: &p256::AffinePoint| {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::P256Sha256 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(p256::AffinePoint, VerifyingKey, |value: &VerifyingKey| {
    use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

    let scheme = value.scheme;
    if scheme != Scheme::P256Sha256 || value.value.len() != 33 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    let pt = EncodedPoint::<p256::NistP256>::from_bytes(&value.value)
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
    Option::from(p256::AffinePoint::from_encoded_point(&pt))
        .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
});
try_from_scheme_ref!(
    VerifyingKey,
    p384::ProjectivePoint,
    |scheme, s: &p384::ProjectivePoint| {
        use elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::P384Sha384 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    p384::ProjectivePoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

        let scheme = value.scheme;
        if scheme != Scheme::P384Sha384 || value.value.len() != 49 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt = EncodedPoint::<p384::NistP384>::from_bytes(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        Option::from(p384::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    p384::AffinePoint,
    |scheme, s: &p384::AffinePoint| {
        use elliptic_curve::sec1::ToEncodedPoint;

        if scheme != Scheme::P384Sha384 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(p384::AffinePoint, VerifyingKey, |value: &VerifyingKey| {
    use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};

    let scheme = value.scheme;
    if scheme != Scheme::P384Sha384 || value.value.len() != 49 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    let pt = EncodedPoint::<p384::NistP384>::from_bytes(&value.value)
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
    Option::from(p384::AffinePoint::from_encoded_point(&pt))
        .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
});
try_from_scheme_ref!(
    VerifyingKey,
    ed448_goldilocks::CompressedEdwardsY,
    |scheme, s: &ed448_goldilocks::CompressedEdwardsY| {
        if scheme != Scheme::Ed448Shake256 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.0.to_vec(),
        })
    }
);
try_from_scheme_ref!(
    ed448_goldilocks::CompressedEdwardsY,
    VerifyingKey,
    |value: &VerifyingKey| {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Self::try_from(&value.value[..])
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    ed448_goldilocks::EdwardsPoint,
    |scheme, s: &ed448_goldilocks::EdwardsPoint| {
        if scheme != Scheme::Ed448Shake256 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.compress().0.to_vec(),
        })
    }
);
try_from_scheme_ref!(
    ed448_goldilocks::EdwardsPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Self::try_from(&value.value[..])
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    jubjub::ExtendedPoint,
    |scheme, s: &jubjub::ExtendedPoint| {
        use jubjub::group::GroupEncoding;

        if scheme != Scheme::RedJubjubBlake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    jubjub::ExtendedPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = jubjub::AffinePoint::try_from(value)?;
        Ok(pt.into())
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    jubjub::AffinePoint,
    |scheme, s: &jubjub::AffinePoint| {
        if scheme != Scheme::RedJubjubBlake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(jubjub::AffinePoint, VerifyingKey, |value: &VerifyingKey| {
    let scheme = value.scheme;
    if scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
    Option::<jubjub::AffinePoint>::from(jubjub::AffinePoint::from_bytes(&bytes)).ok_or(
        Error::General("Error converting verifying key from bytes".to_string()),
    )
});
try_from_scheme_ref!(
    VerifyingKey,
    jubjub::SubgroupPoint,
    |scheme, s: &jubjub::SubgroupPoint| {
        use jubjub::group::GroupEncoding;

        if scheme != Scheme::RedJubjubBlake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    jubjub::SubgroupPoint,
    VerifyingKey,
    |value: &VerifyingKey| {
        use jubjub::group::GroupEncoding;

        let scheme = value.scheme;
        if scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
        Option::<jubjub::SubgroupPoint>::from(jubjub::SubgroupPoint::from_bytes(&bytes)).ok_or(
            Error::General("Error converting verifying key from bytes".to_string()),
        )
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    curve25519::WrappedEdwards,
    |scheme, s: &curve25519::WrappedEdwards| { Self::try_from((scheme, &s.0)) }
);

try_from_scheme_ref!(VerifyingKey, pallas::Point, |scheme, s: &pallas::Point| {
    use group::GroupEncoding;

    if scheme != Scheme::RedPallasBlake2b512 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    Ok(Self {
        scheme,
        value: s.to_bytes().to_vec(),
    })
});
try_from_scheme_ref!(pallas::Point, VerifyingKey, |value: &VerifyingKey| {
    use group::GroupEncoding;

    let scheme = value.scheme;
    if scheme != Scheme::RedPallasBlake2b512 || value.value.len() != 32 {
        return Err(Error::General(
            "Ciphersuite does not match verifying key".to_string(),
        ));
    }
    let bytes = <[u8; 32]>::try_from(value.value.as_slice())
        .expect("Invalid length")
        .into();
    Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes)).ok_or(Error::General(
        "Error converting verifying key from bytes".to_string(),
    ))
});

try_from_scheme_ref!(
    curve25519::WrappedEdwards,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = curve25519::WrappedEdwards::try_from(value)?;
        Ok(Self(pt.0))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    curve25519::WrappedRistretto,
    |scheme, s: &curve25519::WrappedRistretto| { Self::try_from((scheme, &s.0)) }
);
try_from_scheme_ref!(
    curve25519::WrappedRistretto,
    VerifyingKey,
    |value: &VerifyingKey| {
        let pt = curve25519::WrappedRistretto::try_from(value)?;
        Ok(Self(pt.0))
    }
);
try_from_scheme_ref!(
    VerifyingKey,
    decaf377::Element,
    |scheme, s: &decaf377::Element| {
        if scheme != Scheme::RedDecaf377Blake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        use ark_serialize::CanonicalSerialize;

        let mut value = Vec::with_capacity(32);
        s.serialize_compressed(&mut value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;

        Ok(Self { scheme, value })
    }
);
try_from_scheme_ref!(decaf377::Element, VerifyingKey, |value: &VerifyingKey| {
    use ark_serialize::CanonicalDeserialize;

    decaf377::Element::deserialize_compressed(value.value.as_slice())
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
});

impl From<k256::schnorr::VerifyingKey> for VerifyingKey {
    fn from(s: k256::schnorr::VerifyingKey) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::schnorr::VerifyingKey> for VerifyingKey {
    fn from(s: &k256::schnorr::VerifyingKey) -> Self {
        Self {
            scheme: Scheme::K256Taproot,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for k256::schnorr::VerifyingKey {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for k256::schnorr::VerifyingKey {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::K256Taproot {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        match value.value.len() {
            32 => k256::schnorr::VerifyingKey::from_bytes(value.value.as_slice()).map_err(|_| {
                Error::General("Error converting verifying key from bytes".to_string())
            }),
            33 => k256::schnorr::VerifyingKey::from_bytes(&value.value[1..]).map_err(|_| {
                Error::General("Error converting verifying key from bytes".to_string())
            }),
            _ => Err(Error::General(
                "Error converting verifying key from bytes".to_string(),
            )),
        }
    }
}

impl From<ed25519_dalek::VerifyingKey> for VerifyingKey {
    fn from(s: ed25519_dalek::VerifyingKey) -> Self {
        Self::from(&s)
    }
}

impl From<&ed25519_dalek::VerifyingKey> for VerifyingKey {
    fn from(s: &ed25519_dalek::VerifyingKey) -> Self {
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::Ed25519Sha512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes: [u8; 32] =
            value.value.as_slice().try_into().map_err(|_| {
                Error::General("Error converting verifying key from bytes".to_string())
            })?;
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl<S: reddsa::SigType> TryFrom<(Scheme, &reddsa::VerificationKey<S>)> for VerifyingKey {
    type Error = Error;

    fn try_from((scheme, s): (Scheme, &reddsa::VerificationKey<S>)) -> Result<Self, Self::Error> {
        Self::try_from((scheme, *s))
    }
}

impl<S: reddsa::SigType> TryFrom<(Scheme, reddsa::VerificationKey<S>)> for VerifyingKey {
    type Error = Error;

    fn try_from((scheme, s): (Scheme, reddsa::VerificationKey<S>)) -> Result<Self, Self::Error> {
        if scheme != Scheme::RedJubjubBlake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes: [u8; 32] = s.into();
        Ok(Self {
            scheme,
            value: bytes.to_vec(),
        })
    }
}

impl<S: reddsa::SigType> TryFrom<VerifyingKey> for reddsa::VerificationKey<S> {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<S: reddsa::SigType> TryFrom<&VerifyingKey> for reddsa::VerificationKey<S> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if (scheme != Scheme::RedJubjubBlake2b512 && scheme != Scheme::RedPallasBlake2b512)
            || value.value.len() != 32
        {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
        Ok(bytes.try_into()?)
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<(Scheme, decaf377_rdsa::VerificationKey<D>)>
    for VerifyingKey
{
    type Error = Error;

    fn try_from(
        (scheme, s): (Scheme, decaf377_rdsa::VerificationKey<D>),
    ) -> Result<Self, Self::Error> {
        Self::try_from((scheme, &s))
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<(Scheme, &decaf377_rdsa::VerificationKey<D>)>
    for VerifyingKey
{
    type Error = Error;

    fn try_from(
        (scheme, s): (Scheme, &decaf377_rdsa::VerificationKey<D>),
    ) -> Result<Self, Self::Error> {
        if scheme != Scheme::RedDecaf377Blake2b512 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<VerifyingKey> for decaf377_rdsa::VerificationKey<D> {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<D: decaf377_rdsa::Domain> TryFrom<&VerifyingKey> for decaf377_rdsa::VerificationKey<D> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::RedDecaf377Blake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
        Ok(bytes.try_into()?)
    }
}

impl TryFrom<(Scheme, schnorrkel::PublicKey)> for VerifyingKey {
    type Error = Error;

    fn try_from((scheme, s): (Scheme, schnorrkel::PublicKey)) -> Result<Self, Self::Error> {
        Self::try_from((scheme, &s))
    }
}

impl TryFrom<(Scheme, &schnorrkel::PublicKey)> for VerifyingKey {
    type Error = Error;

    fn try_from((scheme, s): (Scheme, &schnorrkel::PublicKey)) -> Result<Self, Self::Error> {
        if scheme != Scheme::SchnorrkelSubstrate {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
}

impl TryFrom<VerifyingKey> for schnorrkel::PublicKey {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for schnorrkel::PublicKey {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::SchnorrkelSubstrate || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        schnorrkel::PublicKey::from_bytes(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
}
