use lit_rust_crypto::*;

use elliptic_curve::{
    PrimeField,
    sec1::{EncodedPoint, FromEncodedPoint},
};
use group::GroupEncoding;
use std::io::{Cursor, Read};

pub trait EcParser {
    type Point: Default + Copy + Clone;
    type Scalar: Default + Copy + Clone;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str>;

    fn parse_points_vec(
        &self,
        reader: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self::Point>, &'static str> {
        let mut points = vec![Self::Point::default(); count];
        for point in points.iter_mut() {
            *point = self.parse_points::<1>(reader)?[0];
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str>;

    fn parse_scalars_vec(
        &self,
        reader: &mut Cursor<&[u8]>,
        count: usize,
    ) -> Result<Vec<Self::Scalar>, &'static str> {
        let mut scalars = vec![Self::Scalar::default(); count];
        for scalar in scalars.iter_mut() {
            *scalar = self.parse_scalars::<1>(reader)?[0];
        }
        Ok(scalars)
    }
}

#[cfg(feature = "k256")]
impl EcParser for k256::Secp256k1 {
    type Point = k256::ProjectivePoint;
    type Scalar = k256::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [k256::ProjectivePoint::default(); N];
        let mut bytes = [4u8; 65];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes[1..]).map_err(
                |_| "tried to read 65 bytes for secp256k1 points but reached end of stream",
            )?;
            let encoded_point = EncodedPoint::<k256::Secp256k1>::from_bytes(bytes)
                .map_err(|_| "invalid secp256k1 point")?;
            *point = Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(
                &encoded_point,
            ))
            .map(k256::ProjectivePoint::from)
            .ok_or("invalid secp256k1 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [k256::Scalar::ZERO; N];
        let mut repr = k256::FieldBytes::default();
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<k256::Scalar>::from(k256::Scalar::from_repr(repr))
                .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "p256")]
impl EcParser for p256::NistP256 {
    type Point = p256::ProjectivePoint;
    type Scalar = p256::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [p256::ProjectivePoint::default(); N];
        let mut bytes = [4u8; 65];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes[1..]).map_err(
                |_| "tried to read 65 bytes for secp256r1 points but reached end of stream",
            )?;
            let encoded_point = EncodedPoint::<p256::NistP256>::from_bytes(bytes)
                .map_err(|_| "invalid secp256r1 point")?;
            *point = Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(
                &encoded_point,
            ))
            .map(p256::ProjectivePoint::from)
            .ok_or("invalid secp256r1 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [p256::Scalar::ZERO; N];
        let mut repr = p256::FieldBytes::default();
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(repr))
                .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "p384")]
impl EcParser for p384::NistP384 {
    type Point = p384::ProjectivePoint;
    type Scalar = p384::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [p384::ProjectivePoint::default(); N];
        let mut bytes = [4u8; 97];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes[1..]).map_err(
                |_| "tried to read 97 bytes for secp384r1 points but reached end of stream",
            )?;
            let encoded_point = EncodedPoint::<p384::NistP384>::from_bytes(bytes)
                .map_err(|_| "invalid secp384r1 point")?;
            *point = Option::<p384::AffinePoint>::from(p384::AffinePoint::from_encoded_point(
                &encoded_point,
            ))
            .map(p384::ProjectivePoint::from)
            .ok_or("invalid secp384r1 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [p384::Scalar::ZERO; N];
        let mut repr = p384::FieldBytes::default();
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<p384::Scalar>::from(p384::Scalar::from_repr(repr))
                .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "curve25519")]
impl EcParser for Ed25519 {
    type Point = curve25519_dalek::EdwardsPoint;
    type Scalar = curve25519_dalek::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [curve25519_dalek::EdwardsPoint::default(); N];
        let mut bytes = [0u8; 32];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 32 bytes for ed25519 points but reached end of stream",
            )?;
            *point = Option::from(curve25519_dalek::EdwardsPoint::from_bytes(&bytes))
                .ok_or("invalid ed25519 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [curve25519_dalek::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<curve25519_dalek::Scalar>::from(
                curve25519_dalek::Scalar::from_canonical_bytes(repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "curve25519")]
impl EcParser for Ristretto25519 {
    type Point = curve25519_dalek::RistrettoPoint;
    type Scalar = curve25519_dalek::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [curve25519_dalek::RistrettoPoint::default(); N];
        let mut bytes = [0u8; 32];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 32 bytes for ristretto25519 points but reached end of stream",
            )?;
            *point = Option::from(curve25519_dalek::RistrettoPoint::from_bytes(&bytes))
                .ok_or("invalid ristretto25519 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [curve25519_dalek::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<curve25519_dalek::Scalar>::from(
                curve25519_dalek::Scalar::from_canonical_bytes(repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "ed448")]
impl EcParser for Ed448 {
    type Point = ed448_goldilocks::EdwardsPoint;
    type Scalar = ed448_goldilocks::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        use elliptic_curve::generic_array::{GenericArray, typenum};

        let mut points = [ed448_goldilocks::EdwardsPoint::default(); N];
        let mut bytes = GenericArray::<u8, typenum::U57>::default();
        for point in points.iter_mut() {
            reader
                .read_exact(&mut bytes)
                .map_err(|_| "tried to read 57 bytes for ed448 points but reached end of stream")?;
            *point = Option::from(ed448_goldilocks::EdwardsPoint::from_bytes(&bytes))
                .ok_or("invalid ed448 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [ed448_goldilocks::Scalar::ZERO; N];
        let mut repr = ed448_goldilocks::ScalarBytes::default();
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<ed448_goldilocks::Scalar>::from(
                ed448_goldilocks::Scalar::from_canonical_bytes(&repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "jubjub")]
impl EcParser for JubJub {
    type Point = jubjub::SubgroupPoint;
    type Scalar = jubjub::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [jubjub::SubgroupPoint::default(); N];
        let mut bytes = [0u8; 32];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 32 bytes for jubjub points but reached end of stream",
            )?;
            *point = Option::from(jubjub::SubgroupPoint::from_bytes(&bytes))
                .ok_or("invalid jubjub point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        use ff::Field;

        let mut scalars = [jubjub::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<jubjub::Scalar>::from(jubjub::Scalar::from_bytes(&repr))
                .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "pasta")]
impl EcParser for pallas::Pallas {
    type Point = pallas::Point;
    type Scalar = pallas::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [pallas::Point::default(); N];
        let mut bytes = [0u8; 32];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 32 bytes for pallas points but reached end of stream",
            )?;
            let repr = bytes.into();
            *point =
                Option::from(pallas::Point::from_bytes(&repr)).ok_or("invalid pallas point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [pallas::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<pallas::Scalar>::from(pallas::Scalar::from_le_bytes(&repr))
                .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "decaf377")]
impl EcParser for Decaf377 {
    type Point = decaf377::Element;
    type Scalar = decaf377::Fr;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [decaf377::Element::default(); N];
        let mut bytes = [0u8; 32];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 32 bytes for decaf377 points but reached end of stream",
            )?;
            *point = Option::from(decaf377::Element::from_bytes(&bytes))
                .ok_or("invalid decaf377 point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [decaf377::Fr::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar =
                decaf377::Fr::from_bytes_checked(&repr).map_err(|_| "Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "bls")]
impl EcParser for blsful::inner_types::InnerBls12381G1 {
    type Point = blsful::inner_types::G1Projective;
    type Scalar = blsful::inner_types::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [blsful::inner_types::G1Projective::default(); N];
        let mut bytes = [0u8; blsful::inner_types::G1Projective::UNCOMPRESSED_BYTES];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 96 bytes for G1Projective points but reached end of stream",
            )?;
            *point = Option::from(blsful::inner_types::G1Projective::from_uncompressed(&bytes))
                .ok_or("invalid G1Projective point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [blsful::inner_types::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<blsful::inner_types::Scalar>::from(
                blsful::inner_types::Scalar::from_repr(repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "bls")]
impl EcParser for blsful::inner_types::InnerBls12381G2 {
    type Point = blsful::inner_types::G2Projective;
    type Scalar = blsful::inner_types::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        let mut points = [blsful::inner_types::G2Projective::default(); N];
        let mut bytes = [0u8; blsful::inner_types::G2Projective::UNCOMPRESSED_BYTES];
        for point in points.iter_mut() {
            reader.read_exact(&mut bytes).map_err(
                |_| "tried to read 192 bytes for G2Projective points but reached end of stream",
            )?;
            *point = Option::from(blsful::inner_types::G2Projective::from_uncompressed(&bytes))
                .ok_or("invalid G2Projective point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [blsful::inner_types::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<blsful::inner_types::Scalar>::from(
                blsful::inner_types::Scalar::from_repr(repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "bls")]
impl EcParser for Bls12381Gt {
    type Point = blsful::inner_types::Gt;
    type Scalar = blsful::inner_types::Scalar;

    fn parse_points<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Point; N], &'static str> {
        use blsful::inner_types::*;

        let mut points = [Gt::default(); N];
        let mut bytes = <Gt as GroupEncoding>::Repr::default();
        for point in points.iter_mut() {
            reader.read_exact(bytes.as_mut()).map_err(
                |_| "tried to read 576 bytes for bls12_381_gt points but reached end of stream",
            )?;
            *point = Option::from(Gt::from_bytes(&bytes)).ok_or("invalid bls12_381_gt point")?;
        }
        Ok(points)
    }

    fn parse_scalars<const N: usize>(
        &self,
        reader: &mut Cursor<&[u8]>,
    ) -> Result<[Self::Scalar; N], &'static str> {
        let mut scalars = [blsful::inner_types::Scalar::ZERO; N];
        let mut repr = [0u8; 32];
        for scalar in scalars.iter_mut() {
            reader
                .read_exact(&mut repr)
                .map_err(|_| "Failed to read enough bytes for the scalar")?;
            *scalar = Option::<blsful::inner_types::Scalar>::from(
                blsful::inner_types::Scalar::from_be_bytes(&repr),
            )
            .ok_or("Invalid scalar bytes")?;
        }
        Ok(scalars)
    }
}

#[cfg(feature = "curve25519")]
#[derive(Copy, Clone, Debug)]
pub struct Ed25519;
#[cfg(feature = "curve25519")]
#[derive(Copy, Clone, Debug)]
pub struct Ristretto25519;
#[cfg(feature = "ed448")]
#[derive(Copy, Clone, Debug)]
pub struct Ed448;
#[cfg(feature = "jubjub")]
#[derive(Copy, Clone, Debug)]
pub struct JubJub;
#[cfg(feature = "decaf377")]
#[derive(Copy, Clone, Debug)]
pub struct Decaf377;
#[cfg(feature = "bls")]
#[derive(Copy, Clone, Debug)]
pub struct Bls12381Gt;
