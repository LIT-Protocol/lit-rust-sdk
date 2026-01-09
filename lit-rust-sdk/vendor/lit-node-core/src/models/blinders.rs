use lit_rust_crypto::{
    blsful::inner_types::*, decaf377, ed448_goldilocks, elliptic_curve::subtle::Choice, jubjub,
    k256, p256, p384, pallas, vsss_rs::curve25519,
};

use serde::{Deserialize, Serialize};

/// Blinders for the different curves for verifiable encryption
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Blinders {
    pub bls_blinder: Option<Scalar>,
    pub k256_blinder: Option<k256::Scalar>,
    pub p256_blinder: Option<p256::Scalar>,
    pub p384_blinder: Option<p384::Scalar>,
    pub ed25519_blinder: Option<curve25519::WrappedScalar>,
    pub ristretto25519_blinder: Option<curve25519::WrappedScalar>,
    pub ed448_blinder: Option<ed448_goldilocks::Scalar>,
    pub jubjub_blinder: Option<jubjub::Scalar>,
    pub decaf377_blinder: Option<decaf377::Fr>,
    pub bls12381g1_blinder: Option<Scalar>,
    pub pallas_blinder: Option<pallas::Scalar>,
}

impl Blinders {
    pub fn are_blinders_set(&self) -> bool {
        self.bls_blinder.is_some()
            || self.k256_blinder.is_some()
            || self.p256_blinder.is_some()
            || self.p384_blinder.is_some()
            || self.ed25519_blinder.is_some()
            || self.ristretto25519_blinder.is_some()
            || self.ed448_blinder.is_some()
            || self.jubjub_blinder.is_some()
            || self.decaf377_blinder.is_some()
            || self.bls12381g1_blinder.is_some()
            || self.pallas_blinder.is_some()
    }

    pub fn any_blinders_invalid(&self) -> bool {
        let mut any = Choice::from(0u8);
        if let Some(bls_blinder) = &self.bls_blinder {
            any |= bls_blinder.is_zero();
        }
        if let Some(k256_blinder) = &self.k256_blinder {
            any |= k256_blinder.is_zero();
        }
        if let Some(p256_blinder) = &self.p256_blinder {
            any |= p256_blinder.is_zero();
        }
        if let Some(p384_blinder) = &self.p384_blinder {
            any |= p384_blinder.is_zero();
        }
        if let Some(ed25519_blinder) = &self.ed25519_blinder {
            any |= ed25519_blinder.is_zero();
        }
        if let Some(ristretto25519_blinder) = &self.ristretto25519_blinder {
            any |= ristretto25519_blinder.is_zero();
        }
        if let Some(jubjub_blinder) = &self.jubjub_blinder {
            any |= jubjub_blinder.is_zero();
        }
        if let Some(decaf377_blinder) = &self.decaf377_blinder {
            any |= decaf377_blinder.is_zero();
        }
        if let Some(bls12381g1_blinder) = &self.bls12381g1_blinder {
            any |= bls12381g1_blinder.is_zero();
        }
        if let Some(pallas_blinder) = &self.pallas_blinder {
            any |= pallas_blinder.is_zero();
        }

        bool::from(any)
    }
}
