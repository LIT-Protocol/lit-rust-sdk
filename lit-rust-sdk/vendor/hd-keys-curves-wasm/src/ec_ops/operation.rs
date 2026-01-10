use crate::ec_ops::consts;
use crate::schnorr::parse_hash;
use crate::{EcParser, HDDerivable};
use lit_rust_crypto::*;

#[cfg(feature = "bls")]
use blsful::inner_types::G2Prepared;
use elliptic_curve::{
    CurveArithmetic, Field, Group, PrimeCurve,
    bigint::U256,
    group::{Curve, GroupEncoding},
    hash2curve::GroupDigest,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
    sec1::ToEncodedPoint,
};
#[cfg(feature = "pasta")]
use ff::PrimeField;
use std::io::{Cursor, Read};
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "jubjub")]
fn redjubjub_generator() -> jubjub::SubgroupPoint {
    use elliptic_curve::group::cofactor::CofactorGroup;
    const SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
        48, 181, 242, 170, 173, 50, 86, 48, 188, 221, 219, 206, 77, 103, 101, 109, 5, 253, 28, 194,
        208, 55, 187, 83, 117, 182, 233, 109, 158, 1, 161, 215,
    ];
    let pt: jubjub::ExtendedPoint = jubjub::AffinePoint::from_bytes(&SPENDAUTHSIG_BASEPOINT_BYTES)
        .unwrap()
        .into();
    pt.into_subgroup().unwrap()
}
#[cfg(feature = "pasta")]
fn redpallas_generator() -> pallas::Point {
    const SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
        99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62,
        124, 24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
    ];
    pallas::Affine::from_bytes(&(SPENDAUTHSIG_BASEPOINT_BYTES.into()))
        .unwrap()
        .into()
}

#[derive(Copy, Clone, Debug)]
pub enum EcCurve {
    #[cfg(feature = "p256")]
    P256(p256::NistP256),
    #[cfg(feature = "p384")]
    P384(p384::NistP384),
    #[cfg(feature = "k256")]
    K256(k256::Secp256k1),
    #[cfg(feature = "curve25519")]
    Ed25519(super::Ed25519),
    #[cfg(feature = "curve25519")]
    Ristretto25519(super::Ristretto25519),
    #[cfg(feature = "ed448")]
    Ed448(super::Ed448),
    #[cfg(feature = "jubjub")]
    JubJub(super::JubJub),
    #[cfg(feature = "bls")]
    Bls12381G1(blsful::inner_types::InnerBls12381G1),
    #[cfg(feature = "bls")]
    Bls12381G2(blsful::inner_types::InnerBls12381G2),
    #[cfg(feature = "bls")]
    Bls12381Gt(super::Bls12381Gt),
    #[cfg(feature = "decaf377")]
    Decaf377(super::Decaf377),
    #[cfg(feature = "pasta")]
    Pallas(pallas::Pallas),
}

impl TryFrom<&[u8]> for EcCurve {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "p256")]
            consts::CURVE_NAME_PRIME256V1 => Ok(Self::P256(p256::NistP256)),
            #[cfg(feature = "p384")]
            consts::CURVE_NAME_SECP384R1 => Ok(Self::P384(p384::NistP384)),
            #[cfg(feature = "k256")]
            consts::CURVE_NAME_SECP256K1 => Ok(Self::K256(k256::Secp256k1)),
            #[cfg(feature = "curve25519")]
            consts::CURVE_NAME_CURVE25519 => Ok(Self::Ed25519(super::Ed25519)),
            #[cfg(feature = "curve25519")]
            consts::CURVE_NAME_RISTRETTO25519 => Ok(Self::Ristretto25519(super::Ristretto25519)),
            #[cfg(feature = "ed448")]
            consts::CURVE_NAME_CURVE448 => Ok(Self::Ed448(super::Ed448)),
            #[cfg(feature = "jubjub")]
            consts::CURVE_NAME_JUBJUB => Ok(Self::JubJub(super::JubJub)),
            #[cfg(feature = "decaf377")]
            consts::CURVE_NAME_DECAF377 => Ok(Self::Decaf377(super::Decaf377)),
            #[cfg(feature = "bls")]
            consts::CURVE_NAME_BLS12381G1 => {
                Ok(Self::Bls12381G1(blsful::inner_types::InnerBls12381G1))
            }
            #[cfg(feature = "bls")]
            consts::CURVE_NAME_BLS12381G2 => {
                Ok(Self::Bls12381G2(blsful::inner_types::InnerBls12381G2))
            }
            #[cfg(feature = "bls")]
            consts::CURVE_NAME_BLS12381GT => Ok(Self::Bls12381Gt(super::Bls12381Gt)),
            #[cfg(feature = "pasta")]
            consts::CURVE_NAME_PALLAS => Ok(Self::Pallas(pallas::Pallas)),
            _ => Err("invalid value for EcCurve"),
        }
    }
}

impl EcCurve {
    pub fn ec_mul(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_bytes().as_ref().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let point = curve.parse_points::<1>(&mut cursor)?;
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = point[0] * scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta"
        )))]
        unimplemented!()
    }

    pub fn ec_add(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta"
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_bytes().as_ref().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0] + points[1];
                    Ok(result.to_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_neg(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_bytes().as_ref().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = -points[0];
                    Ok(result.to_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_equal(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let mut output = 0u8;
                    for (lhs, rhs) in points[0]
                        .to_bytes()
                        .as_ref()
                        .iter()
                        .zip(points[1].to_bytes().as_ref())
                    {
                        output |= lhs ^ rhs;
                    }

                    Ok(vec![output])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let points = curve.parse_points::<2>(&mut cursor)?;
                    let result = points[0].ct_eq(&points[1]);
                    Ok(vec![result.unwrap_u8()])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_is_infinity(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![if result { 1 } else { 0 }])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let result = points[0].is_identity();
                    Ok(vec![result.unwrap_u8()])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_is_valid(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let _ = curve.parse_points::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "bls",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_hash_to_point(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "pasta",
            feature = "bls"
        ))]
        {
            let mut cursor = Cursor::new(data);
            let lengths = self.read_sizes::<1>(&mut cursor)?;
            let position = cursor.position() as usize;
            if lengths[0] > data.len() - position {
                return Err("invalid data length");
            }
            let value = &data[position..position + lengths[0]];
            match self {
                #[cfg(feature = "k256")]
                Self::K256(_) => {
                    let point =
                        k256::Secp256k1::hash_from_bytes::<
                            elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha256>,
                        >(&[value], &[b"secp256k1_XMD:SHA-256_SSWU_RO_"])
                        .expect("hash to curve error");
                    Ok(point.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p256")]
                Self::P256(_) => {
                    let point = p256::NistP256::hash_from_bytes::<
                        elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(&[value], &[b"P256_XMD:SHA-256_SSWU_RO_"])
                    .expect("hash to curve error");
                    Ok(point.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(_) => {
                    let point = p384::NistP384::hash_from_bytes::<
                        elliptic_curve::hash2curve::ExpandMsgXmd<sha2::Sha384>,
                    >(&[value], &[b"P384_XMD:SHA-384_SSWU_RO_"])
                    .expect("hash to curve error");
                    Ok(point.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(_) => {
                    let point = curve25519_dalek::EdwardsPoint::hash_to_curve::<
                        hash2curve::ExpandMsgXmd<sha2::Sha512>,
                    >(value, b"edwards25519_XMD:SHA-512_ELL2_RO_");
                    Ok(point.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(_) => {
                    let point =
                        curve25519_dalek::RistrettoPoint::hash_from_bytes::<sha2::Sha512>(value);
                    Ok(point.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(_) => {
                    let point = ed448_goldilocks::EdwardsPoint::hash::<
                        hash2curve::ExpandMsgXof<sha3::Shake256>,
                    >(value, b"edwards448_XOF:SHAKE-256_ELL2_RO_");
                    Ok(point.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(_) => {
                    let point = jubjub::SubgroupPoint::from(jubjub::ExtendedPoint::hash::<
                        hash2curve::ExpandMsgXmd<blake2::Blake2b512>,
                    >(
                        value,
                        b"jubjub_XMD:BLAKE2B-512_SSWU_RO_",
                    ));
                    Ok(point.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(_) => {
                    use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
                    const DST: &[u8] = b"decaf377_XMD:BLAKE2B-512_ELL2_RO_";
                    let mut expander =
                        ExpandMsgXmd::<blake2::Blake2b512>::expand_message(&[value], &[DST], 96)
                            .expect("expander to work for decaf377");
                    let mut bytes = [0u8; 48];
                    expander.fill_bytes(&mut bytes);
                    let one = decaf377::Fq::from_le_bytes_mod_order(&bytes);
                    expander.fill_bytes(&mut bytes);
                    let two = decaf377::Fq::from_le_bytes_mod_order(&bytes);
                    let point = decaf377::Element::hash_to_curve(&one, &two);
                    Ok(point.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(_) => {
                    let point = blsful::inner_types::G1Projective::hash::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(value, b"BLS12381G1_XMD:SHA-256_SSWU_RO_");
                    Ok(point.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(_) => {
                    let point = blsful::inner_types::G2Projective::hash::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(value, b"BLS12381G2_XMD:SHA-256_SSWU_RO_");
                    Ok(point.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(_) => {
                    use blsful::inner_types::MillerLoopResult;
                    use group::prime::PrimeCurveAffine;

                    let point = blsful::inner_types::G1Projective::hash::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(value, b"BLS12381G1_XMD:SHA-256_SSWU_RO_")
                    .to_affine();
                    let generator = blsful::inner_types::G2Affine::generator();
                    let ref_t = &[(&point, &G2Prepared::from(generator))];
                    let result =
                        blsful::inner_types::multi_miller_loop(ref_t).final_exponentiation();
                    Ok(result.to_bytes().as_ref().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(_) => {
                    use pasta::arithmetic::CurveExt;

                    let hasher = pallas::Point::hash_to_curve("PALLAS_XMD:BLAKE2B-512_SSWU_RO_");
                    let point = hasher(value);
                    Ok(point.to_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn ec_sum_of_products(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            let lengths = self.read_sizes::<1>(&mut cursor)?;
            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = p256::ProjectivePoint::sum_of_products(&points, &scalars);
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = p384::ProjectivePoint::sum_of_products(&points, &scalars);
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = k256::ProjectivePoint::sum_of_products(&points, &scalars);
                    Ok(result.to_encoded_point(false).as_bytes()[1..].to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = curve25519_dalek::EdwardsPoint::sum_of_products(&points, &scalars);
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result =
                        curve25519_dalek::RistrettoPoint::sum_of_products(&points, &scalars);
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = ed448_goldilocks::EdwardsPoint::sum_of_products(&points, &scalars);
                    Ok(result.compress().as_bytes().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = jubjub::SubgroupPoint::sum_of_products(&points, &scalars);
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = decaf377::Element::sum_of_products(&points, &scalars);
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = pallas::Point::sum_of_products(&points, &scalars);
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result =
                        blsful::inner_types::G1Projective::sum_of_products(&points, &scalars);
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result =
                        blsful::inner_types::G2Projective::sum_of_products(&points, &scalars);
                    Ok(result.to_uncompressed().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let points = curve.parse_points_vec(&mut cursor, lengths[0])?;
                    let scalars = curve.parse_scalars_vec(&mut cursor, lengths[0])?;
                    let result = points
                        .into_iter()
                        .zip(scalars)
                        .fold(blsful::inner_types::Gt::IDENTITY, |acc, (p, s)| acc + p * s);
                    Ok(result.to_bytes().as_ref().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    #[cfg(feature = "bls")]
    pub fn ec_pairing(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut cursor = Cursor::new(data);
        let lengths = self.read_sizes::<1>(&mut cursor)?;

        match self {
            Self::Bls12381G1(_) | Self::Bls12381G2(_) | Self::Bls12381Gt(_) => {
                use blsful::inner_types::MillerLoopResult;

                let g1_points = blsful::inner_types::InnerBls12381G1
                    .parse_points_vec(&mut cursor, lengths[0])?;
                let g2_points = blsful::inner_types::InnerBls12381G2
                    .parse_points_vec(&mut cursor, lengths[0])?;
                let points = g1_points
                    .into_iter()
                    .zip(g2_points)
                    .map(|(g1, g2)| (g1.to_affine(), G2Prepared::from(g2.to_affine())))
                    .collect::<Vec<_>>();
                let ref_t = points.iter().map(|(g1, g2)| (g1, g2)).collect::<Vec<_>>();
                let result =
                    blsful::inner_types::multi_miller_loop(ref_t.as_slice()).final_exponentiation();
                Ok(result.to_bytes().as_ref().to_vec())
            }
            _ => Err("pairing operation is not supported for this curve"),
        }
    }

    pub fn scalar_add(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes_rfc_8032().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] + scalars[1];
                    Ok(result.to_repr().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_mul(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes_rfc_8032().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0] * scalars[1];
                    Ok(result.to_repr().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_negate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes_rfc_8032().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = -scalar[0];
                    Ok(result.to_repr().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_invert(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_bytes().to_vec());
                    }
                    let result = scalar[0].invert().expect("scalar is not invertible");
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_bytes().to_vec());
                    }
                    let result = scalar[0].invert().expect("scalar is not invertible");
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_bytes().to_vec());
                    }
                    let result = scalar[0].invert().expect("scalar is not invertible");
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].invert();
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].invert();
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].invert();
                    Ok(result.to_bytes_rfc_8032().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_bytes().to_vec());
                    }
                    let result = scalar[0].invert().expect("scalar is not invertible");
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_bytes().to_vec());
                    }
                    let result = scalar[0].invert().expect("scalar is not invertible");
                    Ok(result.to_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_repr().to_vec());
                    }
                    let result = elliptic_curve::ops::Invert::invert(&scalar[0])
                        .expect("scalar is not invertible");
                    Ok(result.to_repr().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_be_bytes().to_vec());
                    }
                    let result = Field::invert(&scalar[0]).expect("scalar is not invertible");
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_be_bytes().to_vec());
                    }
                    let result = Field::invert(&scalar[0]).expect("scalar is not invertible");
                    Ok(result.to_be_bytes().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    if scalar[0].is_zero().into() {
                        return Ok(scalar[0].to_be_bytes().to_vec());
                    }
                    let result = Field::invert(&scalar[0]).expect("scalar is not invertible");
                    Ok(result.to_be_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_sqrt(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes_rfc_8032().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_repr().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_be_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_be_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].sqrt();
                    if result.is_some().into() {
                        Ok(result.unwrap().to_be_bytes().to_vec())
                    } else {
                        Err("scalar is not a quadratic residue")
                    }
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_equal(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalars = curve.parse_scalars::<2>(&mut cursor)?;
                    let result = scalars[0].ct_eq(&scalars[1]);
                    Ok(vec![result.unwrap_u8()])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_is_zero(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalars[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let scalar = curve.parse_scalars::<1>(&mut cursor)?;
                    let result = scalar[0].is_zero();
                    Ok(vec![result.unwrap_u8()])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_is_valid(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    let _ = curve.parse_scalars::<1>(&mut cursor)?;
                    Ok(vec![1])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_from_wide_bytes(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        match self {
            #[cfg(feature = "p256")]
            Self::P256(_) => {
                use elliptic_curve::bigint::{ArrayEncoding, NonZero, U512};

                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let (modulus, _) = NonZero::<U512>::const_new(U512::from_be_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                ));
                let mut value = U512::from_be_slice(&data[..64]);
                value %= modulus;
                let byte_array = value.to_be_byte_array();
                Ok(byte_array.to_vec())
            }
            #[cfg(feature = "p384")]
            Self::P384(_) => {
                use elliptic_curve::bigint::{ArrayEncoding, NonZero, U768};

                if data.len() < 96 {
                    return Err("invalid operation length. Must be at least 96 bytes");
                }
                let (modulus, _) = NonZero::<U768>::const_new(U768::from_be_hex(
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffc7635d81f4372ddf581a0db248b0a77aecec196accc52973",
                ));
                let mut value = U768::from_be_slice(&data[..96]);
                value %= modulus;
                let byte_array = value.to_be_byte_array();
                Ok(byte_array.to_vec())
            }
            #[cfg(feature = "k256")]
            Self::K256(_) => {
                use elliptic_curve::bigint::U512;

                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let repr = k256::WideBytes::clone_from_slice(&data[..64]);
                let scalar = <k256::Scalar as Reduce<U512>>::reduce_bytes(&repr);
                Ok(scalar.to_bytes().to_vec())
            }
            #[cfg(feature = "curve25519")]
            Self::Ed25519(_) | Self::Ristretto25519(_) => {
                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let scalar = curve25519_dalek::Scalar::from_bytes_mod_order_wide(
                    (&data[..64]).try_into().unwrap(),
                );
                Ok(scalar.to_bytes().to_vec())
            }
            #[cfg(feature = "ed448")]
            Self::Ed448(_) => {
                if data.len() < 114 {
                    return Err("invalid operation length. Must be at least 114 bytes");
                }
                let wide_bytes = ed448_goldilocks::WideScalarBytes::clone_from_slice(&data[..114]);
                let scalar = ed448_goldilocks::Scalar::from_bytes_mod_order_wide(&wide_bytes);
                Ok(scalar.to_bytes_rfc_8032().to_vec())
            }
            #[cfg(feature = "jubjub")]
            Self::JubJub(_) => {
                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let scalar = jubjub::Scalar::from_bytes_wide((&data[..64]).try_into().unwrap());
                Ok(scalar.to_bytes().to_vec())
            }
            #[cfg(feature = "decaf377")]
            Self::Decaf377(_) => {
                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let scalar = decaf377::Fr::from_le_bytes_mod_order(&data[..64]);
                Ok(scalar.to_bytes().to_vec())
            }
            #[cfg(feature = "pasta")]
            Self::Pallas(_) => {
                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let bytes = <[u8; 64]>::try_from(&data[..64]).unwrap();
                let scalar = pallas::Scalar::from_bytes_wide(&bytes);
                Ok(scalar.to_repr().to_vec())
            }
            #[cfg(feature = "bls")]
            Self::Bls12381G1(_) | Self::Bls12381G2(_) | Self::Bls12381Gt(_) => {
                if data.len() < 64 {
                    return Err("invalid operation length. Must be at least 64 bytes");
                }
                let scalar =
                    blsful::inner_types::Scalar::from_bytes_wide((&data[..64]).try_into().unwrap());
                Ok(scalar.to_be_bytes().to_vec())
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    pub fn scalar_hash(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            let lengths = self.read_sizes::<1>(&mut cursor)?;
            let position = cursor.position() as usize;
            if lengths[0] > data.len() - position {
                return Err("invalid operation length");
            }
            let value = &data[position..position + lengths[0]];
            match self {
                #[cfg(feature = "p256")]
                Self::P256(_) => {
                    let scalar = p256::NistP256::hash_to_scalar::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(&[value], &[b"P256_XMD:SHA-256_RO_"])
                    .unwrap();
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "p384")]
                Self::P384(_) => {
                    let scalar = p384::NistP384::hash_to_scalar::<
                        hash2curve::ExpandMsgXmd<sha2::Sha384>,
                    >(&[value], &[b"P384_XMD:SHA-384_RO_"])
                    .unwrap();
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "k256")]
                Self::K256(_) => {
                    let scalar = k256::Secp256k1::hash_to_scalar::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(&[value], &[b"secp256k1_XMD:SHA-256_RO_"])
                    .expect("failed to hash to scalar");
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(_) | Self::Ristretto25519(_) => {
                    let scalar = curve25519_dalek::Scalar::hash_from_bytes::<sha2::Sha512>(value);
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(_) => {
                    let scalar = ed448_goldilocks::Scalar::hash::<
                        hash2curve::ExpandMsgXof<sha3::Shake256>,
                    >(value, b"edwards448_XOF:SHAKE-256_RO_");
                    Ok(scalar.to_bytes_rfc_8032().to_vec())
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(_) => {
                    let scalar = jubjub::Scalar::hash::<hash2curve::ExpandMsgXmd<blake2::Blake2b512>>(
                        value,
                        b"jubjub_XMD:BLAKE2B-512_RO_",
                    );
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(_) => {
                    use blake2::Digest;
                    let bytes = blake2::Blake2b512::digest(value);
                    let scalar = decaf377::Fr::from_le_bytes_mod_order(&bytes);
                    Ok(scalar.to_bytes().to_vec())
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(_) => {
                    let scalar = pallas::Scalar::hash::<hash2curve::ExpandMsgXmd<blake2::Blake2b512>>(
                        value,
                        b"PALLAS_XMD:BLAKE2B-512",
                    );
                    Ok(scalar.to_repr().to_vec())
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(_) | Self::Bls12381G2(_) | Self::Bls12381Gt(_) => {
                    let scalar = blsful::inner_types::Scalar::hash::<
                        hash2curve::ExpandMsgXmd<sha2::Sha256>,
                    >(value, b"BLS12381_XMD:SHA-256_RO_");
                    Ok(scalar.to_be_bytes().to_vec())
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        )))]
        unimplemented!()
    }

    #[cfg(any(feature = "p256", feature = "p384", feature = "k256"))]
    pub fn ecdsa_verify(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut cursor = Cursor::new(data);

        match self {
            #[cfg(feature = "p256")]
            Self::P256(curve) => {
                let points = curve.parse_points::<1>(&mut cursor)?;
                let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                let mut signature_bytes = [0u8; 64];
                cursor
                    .read_exact(&mut signature_bytes)
                    .map_err(|_| "failed to read 64 bytes")?;
                let signature = ecdsa::Signature::<p256::NistP256>::from_slice(&signature_bytes)
                    .map_err(|_| "failed to parse signature")?;
                Ok(vec![
                    self.verify_ecdsa(&points[0], &scalars[0], &signature)?
                        .unwrap_u8(),
                ])
            }
            #[cfg(feature = "p384")]
            Self::P384(curve) => {
                let points = curve.parse_points::<1>(&mut cursor)?;
                let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                let mut signature_bytes = [0u8; 96];
                cursor
                    .read_exact(&mut signature_bytes)
                    .map_err(|_| "failed to read 96 bytes")?;
                let signature = ecdsa::Signature::<p384::NistP384>::from_slice(&signature_bytes)
                    .map_err(|_| "failed to parse signature")?;
                Ok(vec![
                    self.verify_ecdsa(&points[0], &scalars[0], &signature)?
                        .unwrap_u8(),
                ])
            }
            #[cfg(feature = "k256")]
            Self::K256(curve) => {
                let points = curve.parse_points::<1>(&mut cursor)?;
                let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                let mut signature_bytes = [0u8; 64];
                cursor
                    .read_exact(&mut signature_bytes)
                    .map_err(|_| "failed to read 64 bytes")?;
                let signature = ecdsa::Signature::<k256::Secp256k1>::from_slice(&signature_bytes)
                    .map_err(|_| "failed to parse signature")?;
                Ok(vec![
                    self.verify_ecdsa(&points[0], &scalars[0], &signature)?
                        .unwrap_u8(),
                ])
            }
            _ => Err("operation is not supported for this curve"),
        }
    }

    pub fn schnorr_verify1(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta",
        ))]
        {
            let mut cursor = Cursor::new(data);
            let hasher = parse_hash(&mut cursor)?;
            let position = cursor.position() as usize;

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<p256::FieldElement>::from(p256::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = p256::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let s =
                        Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <p256::Scalar as Reduce<U256>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (p256::ProjectivePoint::GENERATOR * s.as_ref() - points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    use elliptic_curve::bigint::U384;

                    cursor.set_position(cursor.position() + 48);
                    let msg = &data[position..position + 48];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 48];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 48 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<p384::FieldElement>::from(p384::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = p384::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 48 bytes")?;
                    let s =
                        Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <p384::Scalar as Reduce<U384>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (p384::ProjectivePoint::GENERATOR * s.as_ref() - points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    use elliptic_curve::group::prime::PrimeCurveAffine;

                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<k256::FieldElement>::from(k256::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = k256::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let s =
                        Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <k256::Scalar as Reduce<U256>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (k256::ProjectivePoint::GENERATOR * s.as_ref() - points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if curve25519_dalek::traits::IsIdentity::is_identity(&r) {
                        return Err("signature r cannot be zero");
                    }

                    let big_r =
                        curve25519_dalek::EdwardsPoint::vartime_double_scalar_mul_basepoint(
                            &e,
                            &-points[0],
                            &s,
                        )
                        .compress();
                    Ok(vec![big_r.ct_eq(&r.compress()).unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if curve25519_dalek::traits::IsIdentity::is_identity(&r) {
                        return Err("signature r cannot be zero");
                    }

                    let big_r =
                        curve25519_dalek::RistrettoPoint::vartime_double_scalar_mul_basepoint(
                            &e,
                            &-points[0],
                            &s,
                        )
                        .compress();
                    Ok(vec![big_r.ct_eq(&r.compress()).unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    cursor.set_position(cursor.position() + 57);
                    let msg = &data[position..position + 57];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }
                    let mut r_bytes = [0u8; 57];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 57 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = ed448_goldilocks::WideScalarBytes::default();
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = ed448_goldilocks::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = (-points[0] * e) + ed448_goldilocks::EdwardsPoint::GENERATOR * s;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = jubjub::Scalar::from_bytes_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = redjubjub_generator() * scalars[0] - points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = pallas::Scalar::from_bytes_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = redpallas_generator() * scalars[0] - points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = decaf377::Fr::from_le_bytes_mod_order(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = decaf377::Element::GENERATOR * scalars[0] - points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 96];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 96 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_compressed(), msg);
                    let e = blsful::inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid e bytes length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = blsful::inner_types::G1Projective::GENERATOR * s - points[0] * e;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    use lit_rust_crypto::blsful::inner_types;

                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 192];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 192 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_compressed(), msg);
                    let e = inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid e bytes length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = inner_types::G2Projective::GENERATOR * s - points[0] * e;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; blsful::inner_types::Gt::BYTES];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 576 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].to_bytes().as_ref(), msg);
                    let e = blsful::inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid e bytes length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = blsful::inner_types::Gt::generator() * s - points[0] * e;
                    let mut output = 0u8;
                    for (lhs, rhs) in big_r.to_bytes().as_ref().iter().zip(r.to_bytes().as_ref()) {
                        output |= lhs ^ rhs;
                    }

                    Ok(vec![output])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta"
        )))]
        unimplemented!()
    }

    pub fn schnorr_verify2(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        #[cfg(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "decaf377",
            feature = "bls",
            feature = "pasta"
        ))]
        {
            let mut cursor = Cursor::new(data);
            let hasher = parse_hash(&mut cursor)?;
            let position = cursor.position() as usize;

            match self {
                #[cfg(feature = "p256")]
                Self::P256(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<p256::FieldElement>::from(p256::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = p256::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let s =
                        Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <p256::Scalar as Reduce<U256>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (p256::ProjectivePoint::GENERATOR * s.as_ref() + points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "p384")]
                Self::P384(curve) => {
                    use elliptic_curve::bigint::U384;

                    cursor.set_position(cursor.position() + 48);
                    let msg = &data[position..position + 48];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 48];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 48 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<p384::FieldElement>::from(p384::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = p384::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 48 bytes")?;
                    let s =
                        Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <p384::Scalar as Reduce<U384>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (p384::ProjectivePoint::GENERATOR * s.as_ref() + points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "k256")]
                Self::K256(curve) => {
                    use elliptic_curve::group::prime::PrimeCurveAffine;

                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let r_bytes = r_bytes.into();
                    let r = Option::<k256::FieldElement>::from(k256::FieldElement::from_bytes(
                        &r_bytes,
                    ))
                    .ok_or("invalid signature r bytes")?;
                    if r.is_zero().into() {
                        return Err("signature r cannot be zero");
                    }
                    let mut bytes = k256::FieldBytes::default();
                    cursor
                        .read_exact(&mut bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let s =
                        Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(bytes))
                            .ok_or("invalid signature s bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_bytes()[1..], msg);
                    let e = <k256::Scalar as Reduce<U256>>::reduce_bytes((&e_bytes[..]).into());

                    let big_r =
                        (k256::ProjectivePoint::GENERATOR * s.as_ref() + points[0] * e).to_affine();

                    Ok(vec![
                        (big_r.is_identity() | big_r.x().ct_eq(&r_bytes)).unwrap_u8(),
                    ])
                }
                #[cfg(feature = "curve25519")]
                Self::Ed25519(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if curve25519_dalek::traits::IsIdentity::is_identity(&r) {
                        return Err("signature r cannot be zero");
                    }

                    let big_r =
                        curve25519_dalek::EdwardsPoint::vartime_double_scalar_mul_basepoint(
                            &e, &points[0], &s,
                        )
                        .compress();
                    Ok(vec![big_r.ct_eq(&r.compress()).unwrap_u8()])
                }
                #[cfg(feature = "curve25519")]
                Self::Ristretto25519(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if curve25519_dalek::traits::IsIdentity::is_identity(&r) {
                        return Err("signature r cannot be zero");
                    }

                    let big_r =
                        curve25519_dalek::RistrettoPoint::vartime_double_scalar_mul_basepoint(
                            &e, &points[0], &s,
                        )
                        .compress();
                    Ok(vec![big_r.ct_eq(&r.compress()).unwrap_u8()])
                }
                #[cfg(feature = "ed448")]
                Self::Ed448(curve) => {
                    cursor.set_position(cursor.position() + 57);
                    let msg = &data[position..position + 57];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }
                    let mut r_bytes = [0u8; 57];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 57 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].compress().as_bytes(), msg);
                    let mut e_arr = ed448_goldilocks::WideScalarBytes::default();
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = ed448_goldilocks::Scalar::from_bytes_mod_order_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = (points[0] * e) + ed448_goldilocks::EdwardsPoint::GENERATOR * s;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "jubjub")]
                Self::JubJub(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = jubjub::Scalar::from_bytes_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }
                    let big_r = redjubjub_generator() * scalars[0] + points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "pasta")]
                Self::Pallas(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = pallas::Scalar::from_bytes_wide(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }
                    let big_r = redpallas_generator() * scalars[0] + points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "decaf377")]
                Self::Decaf377(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 32];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 32 bytes")?;
                    let e_bytes = hasher.compute_challenge(&r_bytes, &points[0].to_bytes(), msg);
                    let mut e_arr = [0u8; 64];
                    e_arr[..e_bytes.len()].copy_from_slice(&e_bytes[..]);
                    let e = decaf377::Fr::from_le_bytes_mod_order(&e_arr);
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let little_r = points[0];
                    if little_r.is_identity() {
                        return Err("signature r cannot be zero");
                    }
                    let big_r = decaf377::Element::GENERATOR * scalars[0] + points[0] * e;
                    Ok(vec![big_r.ct_eq(&little_r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G1(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 96];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 96 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_compressed(), msg);
                    let e = blsful::inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = blsful::inner_types::G1Projective::GENERATOR * s + points[0] * e;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381G2(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; 192];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 192 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, &points[0].to_compressed(), msg);
                    let e = blsful::inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = blsful::inner_types::G2Projective::GENERATOR * s + points[0] * e;
                    Ok(vec![big_r.ct_eq(&r).unwrap_u8()])
                }
                #[cfg(feature = "bls")]
                Self::Bls12381Gt(curve) => {
                    cursor.set_position(cursor.position() + 32);
                    let msg = &data[position..position + 32];
                    let points = curve.parse_points::<1>(&mut cursor)?;
                    if points[0].is_identity().into() {
                        return Err("invalid public key point");
                    }

                    let mut r_bytes = [0u8; blsful::inner_types::Gt::BYTES];
                    cursor
                        .read_exact(&mut r_bytes)
                        .map_err(|_| "failed to read 576 bytes")?;
                    let e_bytes =
                        hasher.compute_challenge(&r_bytes, points[0].to_bytes().as_ref(), msg);
                    let e = blsful::inner_types::Scalar::from_bytes_wide(
                        (&e_bytes[..64]).try_into().expect("invalid length"),
                    );
                    let scalars = curve.parse_scalars::<1>(&mut cursor)?;
                    let s = scalars[0];
                    if s.is_zero().into() {
                        return Err("signature s cannot be zero");
                    }
                    let r = points[0];
                    if r.is_identity().into() {
                        return Err("signature r cannot be zero");
                    }

                    let big_r = blsful::inner_types::Gt::generator() * s + points[0] * e;
                    let mut output = 0u8;
                    for (lhs, rhs) in big_r
                        .to_bytes()
                        .as_ref()
                        .iter()
                        .zip(r.to_bytes().as_ref().iter())
                    {
                        output |= lhs ^ rhs;
                    }

                    Ok(vec![output])
                }
            }
        }
        #[cfg(not(any(
            feature = "p256",
            feature = "p384",
            feature = "k256",
            feature = "curve25519",
            feature = "ed448",
            feature = "jubjub",
            feature = "bls",
            feature = "decaf377",
            feature = "pasta"
        )))]
        unimplemented!()
    }

    #[cfg(feature = "bls")]
    pub fn bls_verify(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut cursor = Cursor::new(data);
        match self {
            Self::Bls12381G1(_) => {
                let lengths = self.read_sizes::<1>(&mut cursor)?;
                let position = cursor.position() as usize;
                let msg = &data[position..position + lengths[0]];
                cursor.set_position(cursor.position() + lengths[0] as u64);
                let g1_points =
                    blsful::inner_types::InnerBls12381G1.parse_points::<1>(&mut cursor)?;
                let g2_points =
                    blsful::inner_types::InnerBls12381G2.parse_points::<1>(&mut cursor)?;
                let pk = blsful::PublicKey::<blsful::Bls12381G2Impl>(g1_points[0]);
                let sig =
                    blsful::Signature::<blsful::Bls12381G2Impl>::ProofOfPossession(g2_points[0]);
                if sig
                    .verify(&pk, msg)
                    .map_err(|_| "failed to verify signature")
                    .is_ok()
                {
                    Ok(vec![1u8])
                } else {
                    Ok(vec![0u8])
                }
            }
            Self::Bls12381G2(_) => {
                let lengths = self.read_sizes::<1>(&mut cursor)?;
                let position = cursor.position() as usize;
                let msg = &data[position..position + lengths[0]];
                cursor.set_position(cursor.position() + lengths[0] as u64);
                let g1_points =
                    blsful::inner_types::InnerBls12381G2.parse_points::<1>(&mut cursor)?;
                let g2_points =
                    blsful::inner_types::InnerBls12381G1.parse_points::<1>(&mut cursor)?;
                let pk = blsful::PublicKey::<blsful::Bls12381G1Impl>(g1_points[0]);
                let sig =
                    blsful::Signature::<blsful::Bls12381G1Impl>::ProofOfPossession(g2_points[0]);
                if sig
                    .verify(&pk, msg)
                    .map_err(|_| "failed to verify signature")
                    .is_ok()
                {
                    Ok(vec![1u8])
                } else {
                    Ok(vec![0u8])
                }
            }
            _ => Err("operation is not supported for this curve"),
        }
    }

    #[cfg(any(feature = "k256", feature = "p256", feature = "p384"))]
    fn verify_ecdsa<C>(
        &self,
        q: &elliptic_curve::ProjectivePoint<C>,
        z: &elliptic_curve::Scalar<C>,
        sig: &ecdsa::Signature<C>,
    ) -> Result<Choice, &'static str>
    where
        C: PrimeCurve + CurveArithmetic,
        ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    {
        let (r, s) = sig.split_scalars();
        if (r.is_zero() | s.is_zero()).into() {
            return Err("invalid signature values. r and s must not be zero");
        }

        let s_inv = *s.invert();
        let u1 = *z * s_inv;
        let u2 = *r * s_inv;
        let x = (elliptic_curve::ProjectivePoint::<C>::generator() * u1 + *q * u2)
            .to_affine()
            .x();
        Ok(r.as_ref()
            .ct_eq(&elliptic_curve::Scalar::<C>::reduce_bytes(&x)))
    }

    fn read_sizes<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[usize; N], &'static str> {
        let mut lengths = [0; N];
        let mut slice = [0u8; 32];
        for l_i in lengths.iter_mut() {
            reader
                .read_exact(&mut slice)
                .map_err(|_| "failed to read 32 bytes")?;
            let num = U256::from_be_slice(&slice);
            let bits = num.bits();
            if bits > 64 {
                return Err("number is too large");
            }
            let words = num.as_words();
            *l_i = words[0] as usize;
        }
        Ok(lengths)
    }
}
