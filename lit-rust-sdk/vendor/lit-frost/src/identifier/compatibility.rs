use crate::*;
use elliptic_curve::PrimeField;

try_from_scheme_ref!(Identifier, k256::Scalar, |scheme, id: &k256::Scalar| {
    match scheme {
        Scheme::K256Sha256 | Scheme::K256Taproot => {
            let bytes = id.to_bytes();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(k256::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::K256Sha256 | Scheme::K256Taproot => {
            let bytes = k256::FieldBytes::clone_from_slice(&id.id);
            Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes))
                .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, p256::Scalar, |scheme, id: &p256::Scalar| {
    match scheme {
        Scheme::P256Sha256 => {
            let bytes = id.to_bytes();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(p256::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::P256Sha256 => {
            let bytes = p256::FieldBytes::clone_from_slice(&id.id);
            Option::<p256::Scalar>::from(p256::Scalar::from_repr(bytes))
                .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, p384::Scalar, |scheme, id: &p384::Scalar| {
    match scheme {
        Scheme::P384Sha384 => {
            let bytes = id.to_bytes();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(p384::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::P384Sha384 => {
            let bytes = p384::FieldBytes::from_slice(&id.id);
            Option::<p384::Scalar>::from(p384::Scalar::from_bytes(bytes))
                .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(
    Identifier,
    curve25519_dalek::Scalar,
    |scheme, id: &curve25519_dalek::Scalar| {
        match scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 | Scheme::SchnorrkelSubstrate => {
                let bytes = id.to_bytes();
                Ok(Self {
                    scheme,
                    id: bytes.to_vec(),
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(curve25519_dalek::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 | Scheme::SchnorrkelSubstrate => {
            let bytes = id
                .id
                .clone()
                .try_into()
                .map_err(|_| Error::General("Invalid identifier".to_string()))?;
            Option::<curve25519_dalek::Scalar>::from(
                curve25519_dalek::Scalar::from_canonical_bytes(bytes),
            )
            .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(
    Identifier,
    ed448_goldilocks::Scalar,
    |scheme, id: &ed448_goldilocks::Scalar| {
        match scheme {
            Scheme::Ed448Shake256 => {
                let bytes = id.to_bytes_rfc_8032();
                Ok(Self {
                    scheme,
                    id: bytes.to_vec(),
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(ed448_goldilocks::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::Ed448Shake256 => {
            let bytes = ed448_goldilocks::ScalarBytes::from_slice(&id.id);
            Option::<ed448_goldilocks::Scalar>::from(
                ed448_goldilocks::Scalar::from_canonical_bytes(bytes),
            )
            .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, jubjub::Scalar, |scheme, id: &jubjub::Scalar| {
    match scheme {
        Scheme::RedJubjubBlake2b512 => {
            let bytes = id.to_bytes();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(jubjub::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::RedJubjubBlake2b512 => {
            let bytes = id
                .id
                .as_slice()
                .try_into()
                .map_err(|_| Error::General("Invalid identifier".to_string()))?;
            Option::<jubjub::Scalar>::from(jubjub::Scalar::from_bytes(bytes))
                .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});

try_from_scheme_ref!(Identifier, pallas::Scalar, |scheme, id: &pallas::Scalar| {
    match scheme {
        Scheme::RedPallasBlake2b512 => {
            let bytes = id.to_le_bytes();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(pallas::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::RedPallasBlake2b512 => {
            let bytes = id
                .id
                .as_slice()
                .try_into()
                .map_err(|_| Error::General("Invalid identifier".to_string()))?;
            Option::<pallas::Scalar>::from(pallas::Scalar::from_le_bytes(bytes))
                .ok_or(Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});

try_from_scheme_ref!(
    Identifier,
    vsss_rs::curve25519_dalek::Scalar,
    |scheme, id: &vsss_rs::curve25519_dalek::Scalar| {
        match scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 | Scheme::SchnorrkelSubstrate => {
                let bytes = id.to_bytes();
                Ok(Self {
                    scheme,
                    id: bytes.to_vec(),
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::Scalar,
    Identifier,
    |id: &Identifier| {
        match id.scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 | Scheme::SchnorrkelSubstrate => {
                let bytes = id
                    .id
                    .clone()
                    .try_into()
                    .map_err(|_| Error::General("Invalid identifier".to_string()))?;
                Option::<vsss_rs::curve25519_dalek::Scalar>::from(
                    vsss_rs::curve25519_dalek::Scalar::from_canonical_bytes(bytes),
                )
                .ok_or(Error::General("Invalid identifier".to_string()))
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(
    Identifier,
    curve25519::WrappedScalar,
    |scheme, id: &curve25519::WrappedScalar| { Self::try_from((scheme, &id.0)) }
);
try_from_scheme_ref!(curve25519::WrappedScalar, Identifier, |id: &Identifier| {
    let scalar = curve25519::WrappedScalar::try_from(id)?;
    Ok(Self(scalar.0))
});
try_from_scheme_ref!(Identifier, decaf377::Fr, |scheme, id: &decaf377::Fr| {
    match scheme {
        Scheme::RedDecaf377Blake2b512 => {
            let bytes = id.to_bytes_le();
            Ok(Self {
                scheme,
                id: bytes.to_vec(),
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(decaf377::Fr, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::RedDecaf377Blake2b512 => {
            let bytes = (&id.id[..])
                .try_into()
                .map_err(|_| Error::General("Invalid identifier".to_string()))?;
            decaf377::Fr::from_bytes_checked(&bytes)
                .map_err(|_| Error::General("Invalid identifier".to_string()))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
