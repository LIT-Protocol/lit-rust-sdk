use super::*;
use lit_rust_crypto::*;

try_from_scheme_ref!(SigningShare, k256::Scalar, |scheme, s: &k256::Scalar| {
    if scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    Ok(Self {
        scheme,
        value: s.to_bytes().to_vec(),
    })
});
try_from_scheme_ref!(k256::Scalar, SigningShare, |value: &SigningShare| {
    use k256::elliptic_curve::ff::PrimeField;

    if (value.scheme != Scheme::K256Sha256 && value.scheme != Scheme::K256Taproot)
        || value.value.len() != 32
    {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = k256::FieldBytes::clone_from_slice(&value.value);
    Option::from(k256::Scalar::from_repr(bytes))
        .ok_or(Error::General("Error converting signing share".to_string()))
});
try_from_scheme_ref!(SigningShare, p256::Scalar, |scheme, s: &p256::Scalar| {
    if scheme != Scheme::P256Sha256 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    Ok(Self {
        scheme,
        value: s.to_bytes().to_vec(),
    })
});
try_from_scheme_ref!(p256::Scalar, SigningShare, |value: &SigningShare| {
    use p256::elliptic_curve::ff::PrimeField;

    if value.scheme != Scheme::P256Sha256 || value.value.len() != 32 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = p256::FieldBytes::clone_from_slice(&value.value);
    Option::from(p256::Scalar::from_repr(bytes))
        .ok_or(Error::General("Error converting signing share".to_string()))
});
try_from_scheme_ref!(SigningShare, p384::Scalar, |scheme, s: &p384::Scalar| {
    if scheme != Scheme::P384Sha384 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    Ok(Self {
        scheme,
        value: s.to_bytes().to_vec(),
    })
});
try_from_scheme_ref!(p384::Scalar, SigningShare, |value: &SigningShare| {
    use p384::elliptic_curve::ff::PrimeField;

    if value.scheme != Scheme::P384Sha384 || value.value.len() != 48 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = p384::FieldBytes::clone_from_slice(&value.value);
    Option::from(p384::Scalar::from_repr(bytes))
        .ok_or(Error::General("Error converting signing share".to_string()))
});
try_from_scheme_ref!(
    SigningShare,
    curve25519_dalek::Scalar,
    |scheme, s: &curve25519_dalek::Scalar| {
        if scheme != Scheme::Ed25519Sha512
            && scheme != Scheme::Ristretto25519Sha512
            && scheme != Scheme::SchnorrkelSubstrate
        {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    curve25519_dalek::Scalar,
    SigningShare,
    |value: &SigningShare| {
        if (value.scheme != Scheme::Ed25519Sha512
            && value.scheme != Scheme::Ristretto25519Sha512
            && value.scheme != Scheme::SchnorrkelSubstrate)
            || value.value.len() != 32
        {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
        Option::from(curve25519_dalek::Scalar::from_canonical_bytes(bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
);
try_from_scheme_ref!(
    SigningShare,
    ed448_goldilocks::Scalar,
    |scheme, s: &ed448_goldilocks::Scalar| {
        if scheme != Scheme::Ed448Shake256 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes_rfc_8032().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    ed448_goldilocks::Scalar,
    SigningShare,
    |value: &SigningShare| {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = ed448_goldilocks::ScalarBytes::clone_from_slice(value.value.as_slice());
        Option::from(ed448_goldilocks::Scalar::from_canonical_bytes(&bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
);

try_from_scheme_ref!(
    SigningShare,
    vsss_rs::curve25519_dalek::Scalar,
    |scheme, s: &vsss_rs::curve25519_dalek::Scalar| {
        if scheme != Scheme::Ed25519Sha512
            && scheme != Scheme::Ristretto25519Sha512
            && scheme != Scheme::SchnorrkelSubstrate
        {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::Scalar,
    SigningShare,
    |value: &SigningShare| {
        if (value.scheme != Scheme::Ed25519Sha512
            && value.scheme != Scheme::Ristretto25519Sha512
            && value.scheme != Scheme::SchnorrkelSubstrate)
            || value.value.len() != 32
        {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
        Option::from(vsss_rs::curve25519_dalek::Scalar::from_canonical_bytes(
            bytes,
        ))
        .ok_or(Error::General("Error converting signing share".to_string()))
    }
);
try_from_scheme_ref!(
    SigningShare,
    curve25519::WrappedScalar,
    |scheme, s: &curve25519::WrappedScalar| { Self::try_from((scheme, &s.0)) }
);
try_from_scheme_ref!(
    curve25519::WrappedScalar,
    SigningShare,
    |value: &SigningShare| {
        let scalar: vsss_rs::curve25519_dalek::Scalar =
            vsss_rs::curve25519_dalek::Scalar::try_from(value)?;
        Ok(Self(scalar))
    }
);
try_from_scheme_ref!(
    SigningShare,
    jubjub::Scalar,
    |scheme, s: &jubjub::Scalar| {
        if scheme != Scheme::RedJubjubBlake2b512 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(jubjub::Scalar, SigningShare, |value: &SigningShare| {
    if value.scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
    Option::from(jubjub::Scalar::from_bytes(&bytes))
        .ok_or(Error::General("Error converting signing share".to_string()))
});
try_from_scheme_ref!(
    SigningShare,
    pallas::Scalar,
    |scheme, s: &pallas::Scalar| {
        if scheme != Scheme::RedPallasBlake2b512 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            value: s.to_le_bytes().to_vec(),
        })
    }
);
try_from_scheme_ref!(pallas::Scalar, SigningShare, |value: &SigningShare| {
    if value.scheme != Scheme::RedPallasBlake2b512 || value.value.len() != 32 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
    Option::from(pallas::Scalar::from_le_bytes(&bytes))
        .ok_or(Error::General("Error converting signing share".to_string()))
});
try_from_scheme_ref!(SigningShare, decaf377::Fr, |scheme, s: &decaf377::Fr| {
    if scheme != Scheme::RedDecaf377Blake2b512 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    Ok(Self {
        scheme,
        value: s.to_bytes_le().to_vec(),
    })
});
try_from_scheme_ref!(decaf377::Fr, SigningShare, |value: &SigningShare| {
    if value.scheme != Scheme::RedDecaf377Blake2b512 || value.value.len() != 32 {
        return Err(Error::General(
            "Signing share scheme does not match ciphersuite".to_string(),
        ));
    }
    let bytes = <[u8; 32]>::try_from(value.value.as_slice()).expect("Invalid length");
    decaf377::Fr::from_bytes_checked(&bytes)
        .map_err(|_| Error::General("Error converting signing share".to_string()))
});
