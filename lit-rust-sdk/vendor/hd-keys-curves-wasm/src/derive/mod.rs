use lit_rust_crypto::elliptic_curve::{Field, Group, PrimeField};

#[cfg(feature = "bls")]
pub mod blsful;
#[cfg(feature = "curve25519")]
pub mod curve25519_dalek_ml;
#[cfg(feature = "decaf377")]
pub mod decaf377;
#[cfg(feature = "ed448")]
pub mod ed448_goldilocks_plus;
#[cfg(feature = "jubjub")]
pub mod jubjub;
#[cfg(feature = "k256")]
pub mod k256;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;
#[cfg(feature = "pasta")]
pub mod pasta;

pub trait HDDeriver: PrimeField {
    fn create(msg: &[u8], dst: &[u8]) -> Self;

    fn hd_derive_secret_key(&self, secret_keys: &[Self]) -> Self {
        secret_keys
            .iter()
            .rfold(Self::ZERO, |acc, sk| acc * self + sk)
    }

    fn hd_derive_public_key<D: HDDerivable<Scalar = Self>>(&self, public_keys: &[D]) -> D {
        if public_keys.is_empty() {
            return D::identity();
        }
        if public_keys.len() == 1 {
            return public_keys[0];
        }
        let powers = get_poly_powers(*self, public_keys.len());
        D::sum_of_products(public_keys, powers.as_slice())
    }
}

pub trait HDDerivable: Group {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self;
}

#[cfg(feature = "elliptic-curve-tools")]
impl<SOP: elliptic_curve_tools::SumOfProducts> HDDerivable for SOP {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        let data = scalars
            .iter()
            .zip(points.iter())
            .map(|(&s, &p)| (s, p))
            .collect::<Vec<_>>();
        <Self as elliptic_curve_tools::SumOfProducts>::sum_of_products(data.as_slice())
    }
}

fn get_poly_powers<D: HDDeriver>(scalar: D, count: usize) -> Vec<D> {
    let mut powers = vec![<D as Field>::ONE; count];
    powers[1] = scalar;
    for i in 2..powers.len() {
        powers[i] = powers[i - 1] * scalar;
    }
    powers
}
