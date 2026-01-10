//! FROST is a threshold signature scheme that allows a group of signers to
//! produce a single signature on a message. The signature is valid if and only
//! if at least `threshold` of the signers have signed the message.
//! FROST is based on the [FROST paper](https://eprint.iacr.org/2020/852.pdf)
//! and the [FROST RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).
//!
//! This crate centers around picking a signature scheme and generating the
//! necessary keys to use FROST. The signature scheme is defined by the
//! [`Scheme`] enum. All other types in this crate are data objects that support
//! the signature schemes.
//!
//! FROST requires 2 rounds to complete a signature. The first round is
//! performed by the signers to generate [`SigningNonces`] and
//! [`SigningCommitments`]. Signers can either generate these values
//! in advance using [`Scheme::pregenerate_signing_nonces`] or generate them
//! on the fly using [`Scheme::signing_round1`]. [`Scheme::signing_round1`] only generates
//! one nonce and commitment to will be used immediately.
//!
//! The second round is performed by the signers to generate a
//! [`SignatureShare`]. [`Scheme::signing_round2`] performs the second round of the
//! signing protocol and generates a [`SignatureShare`].
//!
//! The [`SignatureShare`]s can then be aggregated into a single
//! [`Signature`] using [`Scheme::aggregate`] by the signature recipient.
//! The [`Signature`] can then be verified using [`Scheme::verify`] by anyone.
//!
//! [`SigningShare`]s are generated using distributed key generation (DKG) and
//! help privately by each signer. [`SigningNonces`] must also be treated as
//! secret values known by the signers and used only once per signing operation.
//!
//! [`SigningShare`]s can be converted from the most popular libraries using
//! the [`From`] trait.
#![deny(
    unsafe_code,
    missing_docs,
    missing_debug_implementations,
    unused_qualifications,
    unused_import_braces,
    clippy::unwrap_used
)]
#![warn(
    clippy::cast_precision_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    rust_2018_idioms,
    unused_lifetimes
)]

#[macro_use]
mod macros;
mod error;
mod identifier;
#[cfg(not(feature = "verify_only"))]
mod key_package;
mod signature;
mod signature_share;
mod signing_commitments;
mod signing_nonces;
#[cfg(not(feature = "verify_only"))]
mod signing_share;
mod verifying_key;
mod verifying_share;

use lit_rust_crypto::*;
pub use lit_rust_crypto::{
    self, curve25519_dalek, decaf377, ed448_goldilocks, jubjub, k256, p256, p384, vsss_rs,
};

pub use ed25519_dalek;
pub use schnorrkel;

pub use error::*;
pub use identifier::Identifier;
#[cfg(not(feature = "verify_only"))]
pub use key_package::KeyPackage;
pub use signature::Signature;
pub use signature_share::SignatureShare;
pub use signing_commitments::SigningCommitments;
pub use signing_nonces::SigningNonces;
#[cfg(not(feature = "verify_only"))]
pub use signing_share::SigningShare;
pub use verifying_key::VerifyingKey;
pub use verifying_share::VerifyingShare;

#[cfg(not(feature = "verify_only"))]
use core::num::NonZeroU8;
use frost_core::Ciphersuite;
#[cfg(not(feature = "verify_only"))]
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

#[cfg(not(feature = "verify_only"))]
/// Export the RedJubJub Generator point
pub fn red_jubjub_generator() -> jubjub::SubgroupPoint {
    <frost_redjubjub::JubjubGroup as frost_core::Group>::generator()
}


/// The FROST supported signature schemes
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy, Default)]
#[repr(u8)]
pub enum Scheme {
    #[default]
    /// Compute the Ed25519 signature using the SHA-512 hash function
    Ed25519Sha512 = 1,
    /// Compute the Ed448 signature using the SHAKE-256 hash function
    Ed448Shake256 = 2,
    /// Compute the Ristretto25519 signature using the SHA-512 hash function
    Ristretto25519Sha512 = 3,
    /// Compute the Secp256k1 schnorr signature using the SHA-256 hash function
    K256Sha256 = 4,
    /// Compute the NistP256 schnorr signature using the SHA-256 hash function
    P256Sha256 = 5,
    /// Compute the NistP384 schnorr signature using the SHA-384 hash function
    P384Sha384 = 6,
    /// Compute the RedJubjub schnorr signature using the Blake2b-512 hash function
    RedJubjubBlake2b512 = 7,
    /// Compute the Secp256k1 schnorr signature using the taproot hash function
    K256Taproot = 8,
    /// Compute the RedDecaf377 schnorr signature using the Blake2b-512 hash function
    RedDecaf377Blake2b512 = 9,
    /// Compute the Schnorrkel signature using the Merlin-Strobe128 hash function
    /// for the Polkadot substrate chain
    SchnorrkelSubstrate = 10,
    /// Compute the RedPallas schnorr signature using the Blake2b-512 hash function
    RedPallasBlake2b512 = 11,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519Sha512" | "FROST-ED25519-SHA512-v1" => Ok(Self::Ed25519Sha512),
            "Ed448Shake256" | "FROST-ED448-SHAKE256-v1" => Ok(Self::Ed448Shake256),
            "Ristretto25519Sha512" | "FROST-RISTRETTO255-SHA512-v1" => {
                Ok(Self::Ristretto25519Sha512)
            }
            "K256Sha256" | "FROST-secp256k1-SHA256-v1" => Ok(Self::K256Sha256),
            "P256Sha256" | "FROST-P256-SHA256-v1" => Ok(Self::P256Sha256),
            "P384Sha384" | "FROST-P384-SHA384-v1" => Ok(Self::P384Sha384),
            "RedJubjubBlake2b512" | "FROST-RedJubjub-BLAKE2b-512-v1" => {
                Ok(Self::RedJubjubBlake2b512)
            }
            "K256Taproot" | "FROST-secp256k1-Taproot-v1" => Ok(Self::K256Taproot),
            "RedDecaf377Blake2b512" | "FROST-Decaf377-BLAKE2b-512-v1" => {
                Ok(Self::RedDecaf377Blake2b512)
            }
            "SchnorrkelSubstrate" | "FROST-Schnorrkel-Merlin-Strobe128-v1" => {
                Ok(Self::SchnorrkelSubstrate)
            }
            "RedPallasBlake2b512" | "FROST(Pallas, BLAKE2b-512)" => Ok(Self::RedPallasBlake2b512),
            _ => Err(Error::General(format!("Unknown scheme: {}", s))),
        }
    }
}

impl TryFrom<u8> for Scheme {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ed25519Sha512),
            2 => Ok(Self::Ed448Shake256),
            3 => Ok(Self::Ristretto25519Sha512),
            4 => Ok(Self::K256Sha256),
            5 => Ok(Self::P256Sha256),
            6 => Ok(Self::P384Sha384),
            7 => Ok(Self::RedJubjubBlake2b512),
            8 => Ok(Self::K256Taproot),
            9 => Ok(Self::RedDecaf377Blake2b512),
            10 => Ok(Self::SchnorrkelSubstrate),
            11 => Ok(Self::RedPallasBlake2b512),
            _ => Err(Error::General(format!("Unknown scheme: {}", value))),
        }
    }
}

impl Serialize for Scheme {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(*self as u8)
        }
    }
}

impl<'de> Deserialize<'de> for Scheme {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let u = u8::deserialize(d)?;
            Self::try_from(u).map_err(serde::de::Error::custom)
        }
    }
}

impl Scheme {
    #[cfg(not(feature = "verify_only"))]
    /// Pregenerate a `count` of signing nonces and commitments that can be used
    /// later to sign a message. These nonce MUST only be used once, otherwise
    /// the long-lived signing key will be leaked.
    pub fn pregenerate_signing_nonces<R: CryptoRng + RngCore>(
        &self,
        count: NonZeroU8,
        secret_share: &SigningShare,
        rng: &mut R,
    ) -> FrostResult<(Vec<SigningNonces>, Vec<SigningCommitments>)> {
        match self {
            Self::Ed25519Sha512 => {
                preprocess::<frost_ed25519::Ed25519Sha512, R>(count, secret_share, rng)
            }
            Self::Ed448Shake256 => {
                preprocess::<frost_ed448::Ed448Shake256, R>(count, secret_share, rng)
            }
            Self::Ristretto25519Sha512 => {
                preprocess::<frost_ristretto255::Ristretto255Sha512, R>(count, secret_share, rng)
            }
            Self::K256Sha256 => {
                preprocess::<frost_secp256k1::Secp256K1Sha256, R>(count, secret_share, rng)
            }
            Self::P256Sha256 => preprocess::<frost_p256::P256Sha256, R>(count, secret_share, rng),
            Self::P384Sha384 => preprocess::<frost_p384::P384Sha384, R>(count, secret_share, rng),
            Self::RedJubjubBlake2b512 => {
                preprocess::<frost_redjubjub::JubjubBlake2b512, R>(count, secret_share, rng)
            }
            Self::K256Taproot => {
                preprocess::<frost_taproot::Secp256K1Taproot, R>(count, secret_share, rng)
            }
            Self::RedDecaf377Blake2b512 => {
                preprocess::<frost_decaf377::Decaf377Blake2b512, R>(count, secret_share, rng)
            }
            Self::SchnorrkelSubstrate => preprocess::<
                frost_schnorrkel25519::Schnorrkel25519Merlin,
                R,
            >(count, secret_share, rng),
            Self::RedPallasBlake2b512 => {
                preprocess::<frost_redpallas::PallasBlake2b512, R>(count, secret_share, rng)
            }
        }
    }

    #[cfg(not(feature = "verify_only"))]
    /// Compute the first round of the signing protocol if no pregenerated nonces and commitments are available.
    pub fn signing_round1<R: CryptoRng + RngCore>(
        &self,
        secret_share: &SigningShare,
        rng: &mut R,
    ) -> FrostResult<(SigningNonces, SigningCommitments)> {
        if secret_share.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for secret_share: expected {}, found {}",
                self, secret_share.scheme
            )));
        }
        match self {
            Self::Ed25519Sha512 => round1::<frost_ed25519::Ed25519Sha512, R>(secret_share, rng),
            Self::Ed448Shake256 => round1::<frost_ed448::Ed448Shake256, R>(secret_share, rng),
            Self::Ristretto25519Sha512 => {
                round1::<frost_ristretto255::Ristretto255Sha512, R>(secret_share, rng)
            }
            Self::K256Sha256 => round1::<frost_secp256k1::Secp256K1Sha256, R>(secret_share, rng),
            Self::P256Sha256 => round1::<frost_p256::P256Sha256, R>(secret_share, rng),
            Self::P384Sha384 => round1::<frost_p384::P384Sha384, R>(secret_share, rng),
            Self::RedJubjubBlake2b512 => {
                round1::<frost_redjubjub::JubjubBlake2b512, R>(secret_share, rng)
            }
            Self::K256Taproot => round1::<frost_taproot::Secp256K1Taproot, R>(secret_share, rng),
            Self::RedDecaf377Blake2b512 => {
                round1::<frost_decaf377::Decaf377Blake2b512, R>(secret_share, rng)
            }
            Self::SchnorrkelSubstrate => {
                round1::<frost_schnorrkel25519::Schnorrkel25519Merlin, R>(secret_share, rng)
            }
            Self::RedPallasBlake2b512 => {
                round1::<frost_redpallas::PallasBlake2b512, R>(secret_share, rng)
            }
        }
    }

    #[cfg(not(feature = "verify_only"))]
    /// Compute the second round of the signing protocol and generate a signature.
    pub fn signing_round2(
        &self,
        message: &[u8],
        signing_commitments: &[(Identifier, SigningCommitments)],
        signing_nonce: &SigningNonces,
        key_package: &KeyPackage,
    ) -> FrostResult<SignatureShare> {
        if key_package.identifier.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for key_package: expected {}, found {}",
                self, key_package.identifier.scheme
            )));
        }
        if signing_nonce.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for signing_nonce: expected {}, found {}",
                self, signing_nonce.scheme
            )));
        }
        if signing_commitments
            .iter()
            .any(|(id, c)| id.scheme != *self || c.scheme != *self)
        {
            return Err(Error::General(
                "mismatched schemes for signing_commitments".to_string(),
            ));
        }
        match self {
            Self::Ed25519Sha512 => round2::<frost_ed25519::Ed25519Sha512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::Ed448Shake256 => round2::<frost_ed448::Ed448Shake256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::Ristretto25519Sha512 => round2::<frost_ristretto255::Ristretto255Sha512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::K256Sha256 => round2::<frost_secp256k1::Secp256K1Sha256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::P256Sha256 => round2::<frost_p256::P256Sha256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::P384Sha384 => round2::<frost_p384::P384Sha384>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::RedJubjubBlake2b512 => round2::<frost_redjubjub::JubjubBlake2b512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::K256Taproot => round2::<frost_taproot::Secp256K1Taproot>(
                Sha256::digest(message).as_slice(),
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::RedDecaf377Blake2b512 => round2::<frost_decaf377::Decaf377Blake2b512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::SchnorrkelSubstrate => round2::<frost_schnorrkel25519::Schnorrkel25519Merlin>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::RedPallasBlake2b512 => round2::<frost_redpallas::PallasBlake2b512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
        }
    }

    /// Combine the signature shares into a single signature.
    pub fn aggregate(
        &self,
        message: &[u8],
        signing_commitments: &[(Identifier, SigningCommitments)],
        signature_shares: &[(Identifier, SignatureShare)],
        signer_pubkeys: &[(Identifier, VerifyingShare)],
        verifying_key: &VerifyingKey,
    ) -> FrostResult<Signature> {
        if signer_pubkeys
            .iter()
            .any(|(id, v)| id.scheme != *self || v.scheme != *self)
        {
            return Err(Error::General(
                "mismatched schemes for signer_pubkeys".to_string(),
            ));
        }
        if signing_commitments
            .iter()
            .any(|(id, c)| id.scheme != *self || c.scheme != *self)
        {
            return Err(Error::General(
                "mismatched schemes for signing_commitments".to_string(),
            ));
        }
        if signature_shares
            .iter()
            .any(|(id, s)| id.scheme != *self || s.scheme != *self)
        {
            return Err(Error::General(
                "mismatched schemes for signature_shares".to_string(),
            ));
        }
        if verifying_key.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for verifying_key: expected {}, found {}",
                self, verifying_key.scheme
            )));
        }
        match self {
            Self::Ed25519Sha512 => aggregate::<frost_ed25519::Ed25519Sha512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::Ed448Shake256 => aggregate::<frost_ed448::Ed448Shake256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::Ristretto25519Sha512 => aggregate::<frost_ristretto255::Ristretto255Sha512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::K256Sha256 => aggregate::<frost_secp256k1::Secp256K1Sha256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::P256Sha256 => aggregate::<frost_p256::P256Sha256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::P384Sha384 => aggregate::<frost_p384::P384Sha384>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::RedJubjubBlake2b512 => aggregate::<frost_redjubjub::JubjubBlake2b512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::K256Taproot => {
                let signature = aggregate::<frost_taproot::Secp256K1Taproot>(
                    Sha256::digest(message).as_slice(),
                    signing_commitments,
                    signature_shares,
                    signer_pubkeys,
                    verifying_key,
                )?;
                // The Taproot signature requires only 64 bytes
                // which is correctly handled here for dropping the correct bytes
                let sig: k256::schnorr::Signature = signature.try_into()?;
                // Now convert it back in the correct form
                Ok(sig.into())
            }
            Self::RedDecaf377Blake2b512 => aggregate::<frost_decaf377::Decaf377Blake2b512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::SchnorrkelSubstrate => {
                let signature = aggregate::<frost_schnorrkel25519::Schnorrkel25519Merlin>(
                    message,
                    signing_commitments,
                    signature_shares,
                    signer_pubkeys,
                    verifying_key,
                )?;
                // The Schnorrkel signature requires some bits set
                // to indicate the signature is a Schnorrkel signature
                // Handle that here since the default frost signature does not.
                let sig: schnorrkel::Signature = signature.try_into()?;
                // Now convert it back with the correct bits set
                Ok(sig.into())
            }
            Self::RedPallasBlake2b512 => aggregate::<frost_redpallas::PallasBlake2b512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
        }
    }

    /// Verify a purported signature over message made by this verification key.
    pub fn verify(
        &self,
        message: &[u8],
        verifying_key: &VerifyingKey,
        signature: &Signature,
    ) -> FrostResult<()> {
        if verifying_key.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for verifying_key: expected {}, found {}",
                self, verifying_key.scheme
            )));
        }
        if signature.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for signature: expected {}, found {}",
                self, signature.scheme
            )));
        }
        match self {
            Self::Ed25519Sha512 => {
                verify::<frost_ed25519::Ed25519Sha512>(message, verifying_key, signature)
            }
            Self::Ed448Shake256 => {
                verify::<frost_ed448::Ed448Shake256>(message, verifying_key, signature)
            }
            Self::Ristretto25519Sha512 => {
                verify::<frost_ristretto255::Ristretto255Sha512>(message, verifying_key, signature)
            }
            Self::K256Sha256 => {
                verify::<frost_secp256k1::Secp256K1Sha256>(message, verifying_key, signature)
            }
            Self::P256Sha256 => verify::<frost_p256::P256Sha256>(message, verifying_key, signature),
            Self::P384Sha384 => verify::<frost_p384::P384Sha384>(message, verifying_key, signature),
            Self::RedJubjubBlake2b512 => {
                verify::<frost_redjubjub::JubjubBlake2b512>(message, verifying_key, signature)
            }
            Self::K256Taproot => verify::<frost_taproot::Secp256K1Taproot>(
                Sha256::digest(message).as_slice(),
                verifying_key,
                signature,
            ),
            Self::RedDecaf377Blake2b512 => {
                verify::<frost_decaf377::Decaf377Blake2b512>(message, verifying_key, signature)
            }
            Self::SchnorrkelSubstrate => verify::<frost_schnorrkel25519::Schnorrkel25519Merlin>(
                message,
                verifying_key,
                signature,
            ),
            Self::RedPallasBlake2b512 => {
                verify::<frost_redpallas::PallasBlake2b512>(message, verifying_key, signature)
            }
        }
    }

    #[cfg(not(feature = "verify_only"))]
    /// Get the [`VerifyingShare`] from a [`SigningShare`]
    pub fn verifying_share(&self, signing_share: &SigningShare) -> FrostResult<VerifyingShare> {
        if signing_share.scheme != *self {
            return Err(Error::General(format!(
                "mismatched schemes for signing_share: expected {}, found {}",
                self, signing_share.scheme
            )));
        }
        match self {
            Self::Ed25519Sha512 => verifying_share::<frost_ed25519::Ed25519Sha512>(signing_share),
            Self::Ed448Shake256 => verifying_share::<frost_ed448::Ed448Shake256>(signing_share),
            Self::Ristretto25519Sha512 => {
                verifying_share::<frost_ristretto255::Ristretto255Sha512>(signing_share)
            }
            Self::K256Sha256 => verifying_share::<frost_secp256k1::Secp256K1Sha256>(signing_share),
            Self::P256Sha256 => verifying_share::<frost_p256::P256Sha256>(signing_share),
            Self::P384Sha384 => verifying_share::<frost_p384::P384Sha384>(signing_share),
            Self::RedJubjubBlake2b512 => {
                verifying_share::<frost_redjubjub::JubjubBlake2b512>(signing_share)
            }
            Self::K256Taproot => verifying_share::<frost_taproot::Secp256K1Taproot>(signing_share),
            Self::RedDecaf377Blake2b512 => {
                verifying_share::<frost_decaf377::Decaf377Blake2b512>(signing_share)
            }
            Self::SchnorrkelSubstrate => {
                verifying_share::<frost_schnorrkel25519::Schnorrkel25519Merlin>(signing_share)
            }
            Self::RedPallasBlake2b512 => {
                verifying_share::<frost_redpallas::PallasBlake2b512>(signing_share)
            }
        }
    }

    pub(crate) const fn scalar_len(&self) -> FrostResult<usize> {
        match self {
            Self::Ed25519Sha512 => Ok(32),
            Self::Ed448Shake256 => Ok(57),
            Self::Ristretto25519Sha512 => Ok(32),
            Self::K256Sha256 => Ok(32),
            Self::P256Sha256 => Ok(32),
            Self::P384Sha384 => Ok(48),
            Self::RedJubjubBlake2b512 => Ok(32),
            Self::K256Taproot => Ok(32),
            Self::RedDecaf377Blake2b512 => Ok(32),
            Self::SchnorrkelSubstrate => Ok(32),
            Self::RedPallasBlake2b512 => Ok(32),
        }
    }

    pub(crate) const fn byte_order(&self) -> FrostResult<ByteOrder> {
        match self {
            Self::Ed25519Sha512
            | Self::Ristretto25519Sha512
            | Self::Ed448Shake256
            | Self::RedJubjubBlake2b512
            | Self::RedDecaf377Blake2b512
            | Self::SchnorrkelSubstrate
            | Self::RedPallasBlake2b512 => Ok(ByteOrder::LittleEndian),
            Self::P256Sha256 | Self::K256Sha256 | Self::K256Taproot | Self::P384Sha384 => {
                Ok(ByteOrder::BigEndian)
            }
        }
    }

    pub(crate) const fn compressed_point_len(&self) -> FrostResult<usize> {
        match self {
            Self::Ed25519Sha512 => Ok(32),
            Self::Ed448Shake256 => Ok(57),
            Self::Ristretto25519Sha512 => Ok(32),
            Self::K256Sha256 => Ok(33),
            Self::P256Sha256 => Ok(33),
            Self::P384Sha384 => Ok(49),
            Self::RedJubjubBlake2b512 => Ok(32),
            Self::K256Taproot => Ok(33),
            Self::RedDecaf377Blake2b512 => Ok(32),
            Self::SchnorrkelSubstrate => Ok(32),
            Self::RedPallasBlake2b512 => Ok(32),
        }
    }

    pub(crate) const fn commitment_len(&self) -> FrostResult<usize> {
        match self {
            Self::Ed25519Sha512 => Ok(69),
            Self::Ed448Shake256 => Ok(119),
            Self::Ristretto25519Sha512 => Ok(69),
            Self::K256Sha256 => Ok(71),
            Self::P256Sha256 => Ok(71),
            Self::P384Sha384 => Ok(103),
            Self::RedJubjubBlake2b512 => Ok(69),
            Self::K256Taproot => Ok(71),
            Self::RedDecaf377Blake2b512 => Ok(69),
            Self::SchnorrkelSubstrate => Ok(69),
            Self::RedPallasBlake2b512 => Ok(69),
        }
    }

    pub(crate) const fn signature_len(&self) -> FrostResult<usize> {
        match self {
            Self::Ed25519Sha512 => Ok(64),
            Self::Ed448Shake256 => Ok(114),
            Self::Ristretto25519Sha512 => Ok(64),
            Self::K256Sha256 => Ok(65),
            Self::P256Sha256 => Ok(65),
            Self::P384Sha384 => Ok(97),
            Self::RedJubjubBlake2b512 => Ok(64),
            Self::K256Taproot => Ok(65),
            Self::RedDecaf377Blake2b512 => Ok(64),
            Self::SchnorrkelSubstrate => Ok(64),
            Self::RedPallasBlake2b512 => Ok(64),
        }
    }

    #[cfg(not(feature = "verify_only"))]
    /// Perform a key generation with a trusted dealer.
    pub fn generate_with_trusted_dealer<R: CryptoRng + RngCore>(
        &self,
        min_signers: u16,
        max_signers: u16,
        rng: &mut R,
    ) -> FrostResult<(BTreeMap<Identifier, SigningShare>, VerifyingKey)> {
        match self {
            Self::Ed25519Sha512 => generate_with_trusted_dealer::<frost_ed25519::Ed25519Sha512, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::Ed448Shake256 => generate_with_trusted_dealer::<frost_ed448::Ed448Shake256, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::Ristretto25519Sha512 => generate_with_trusted_dealer::<
                frost_ristretto255::Ristretto255Sha512,
                R,
            >(min_signers, max_signers, rng),
            Self::K256Sha256 => {
                generate_with_trusted_dealer::<frost_secp256k1::Secp256K1Sha256, R>(
                    min_signers,
                    max_signers,
                    rng,
                )
            }
            Self::P256Sha256 => generate_with_trusted_dealer::<frost_p256::P256Sha256, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::P384Sha384 => generate_with_trusted_dealer::<frost_p384::P384Sha384, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::RedJubjubBlake2b512 => generate_with_trusted_dealer::<
                frost_redjubjub::JubjubBlake2b512,
                R,
            >(min_signers, max_signers, rng),
            Self::K256Taproot => {
                generate_with_trusted_dealer::<frost_taproot::Secp256K1Taproot, R>(
                    min_signers,
                    max_signers,
                    rng,
                )
            }
            Self::RedDecaf377Blake2b512 => generate_with_trusted_dealer::<
                frost_decaf377::Decaf377Blake2b512,
                R,
            >(min_signers, max_signers, rng),
            Self::SchnorrkelSubstrate => generate_with_trusted_dealer::<
                frost_schnorrkel25519::Schnorrkel25519Merlin,
                R,
            >(min_signers, max_signers, rng),
            Self::RedPallasBlake2b512 => generate_with_trusted_dealer::<
                frost_redpallas::PallasBlake2b512,
                R,
            >(min_signers, max_signers, rng),
        }
    }

    /// Return the user-friendly name of the ciphersuite
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519Sha512 => "Ed25519Sha512",
            Self::Ed448Shake256 => "Ed448Shake256",
            Self::Ristretto25519Sha512 => "Ristretto25519Sha512",
            Self::K256Sha256 => "K256Sha256",
            Self::P256Sha256 => "P256Sha256",
            Self::P384Sha384 => "P384Sha384",
            Self::RedJubjubBlake2b512 => "RedJubjubBlake2b512",
            Self::K256Taproot => "K256Taproot",
            Self::RedDecaf377Blake2b512 => "RedDecaf377Blake2b512",
            Self::SchnorrkelSubstrate => "SchnorrkelSubstrate",
            Self::RedPallasBlake2b512 => "RedPallasBlake2b512",
        }
    }
}

/// The byte order for the ciphersuite
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub enum ByteOrder {
    /// Big endian byte order
    #[default]
    BigEndian,
    /// Little endian byte order
    LittleEndian,
}

fn verify<C: Ciphersuite>(
    message: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
) -> FrostResult<()> {
    let verifying_key: frost_core::VerifyingKey<C> = verifying_key.try_into()?;
    let signature: frost_core::Signature<C> = signature.try_into()?;
    if !verifying_key.is_valid() || !signature.is_valid() {
        return Err(Error::General("Error verifying signature".to_string()));
    }
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::General("Error verifying signature".to_string()))
}

#[cfg(not(feature = "verify_only"))]
fn verifying_share<C: Ciphersuite>(signing_share: &SigningShare) -> FrostResult<VerifyingShare> {
    let signing_share: frost_core::keys::SigningShare<C> = signing_share.try_into()?;
    let verifying_share = frost_core::keys::VerifyingShare::<C>::from(signing_share);
    Ok(verifying_share.into())
}

fn aggregate<C: Ciphersuite>(
    message: &[u8],
    signing_commitments: &[(Identifier, SigningCommitments)],
    signature_shares: &[(Identifier, SignatureShare)],
    signer_pubkeys: &[(Identifier, VerifyingShare)],
    verifying_key: &VerifyingKey,
) -> FrostResult<Signature> {
    let signing_commitment_map =
        create_frost_signing_commitments_from_bytes::<C>(signing_commitments)?;
    if signing_commitment_map
        .iter()
        .any(|(i, c)| !i.is_valid() && !c.is_valid())
    {
        return Err(Error::General("Error aggregating signature".to_string()));
    }
    let signature_shares_map = create_frost_signing_shares_from_bytes::<C>(signature_shares)?;
    if signature_shares_map
        .iter()
        .any(|(i, s)| !i.is_valid() && !s.is_valid())
    {
        return Err(Error::General("Error aggregating signature".to_string()));
    }
    let mut signer_pubkeys_map = BTreeMap::new();
    for (index, pubkey) in signer_pubkeys {
        let index: frost_core::Identifier<C> = index.try_into()?;
        let pubkey: frost_core::keys::VerifyingShare<C> = pubkey.try_into()?;
        if !index.is_valid() && !pubkey.is_valid() {
            return Err(Error::General("Error aggregating signature".to_string()));
        }
        signer_pubkeys_map.insert(index, pubkey);
    }
    let verifying_key: frost_core::VerifyingKey<C> = verifying_key.try_into()?;
    if !verifying_key.is_valid() {
        return Err(Error::General("Error aggregating signature".to_string()));
    }
    let pubkey_package =
        frost_core::keys::PublicKeyPackage::<C>::new(signer_pubkeys_map, verifying_key);
    if !pubkey_package.is_valid() {
        return Err(Error::General("Error aggregating signature".to_string()));
    }
    let signing_package = frost_core::SigningPackage::<C>::new(signing_commitment_map, message);
    if !signing_package.is_valid() {
        return Err(Error::General("Error aggregating signature".to_string()));
    }

    let signature =
        frost_core::aggregate::<C>(&signing_package, &signature_shares_map, &pubkey_package)
            .map_err(|e| match e {
                frost_core::Error::InvalidSignatureShare { culprit } => {
                    Error::Cheaters(vec![culprit.into()])
                }
                ee => ee.into(),
            })?;
    Ok(signature.into())
}

#[cfg(not(feature = "verify_only"))]
fn round2<C: Ciphersuite>(
    message: &[u8],
    signing_commitments: &[(Identifier, SigningCommitments)],
    signing_nonce: &SigningNonces,
    key_package: &KeyPackage,
) -> FrostResult<SignatureShare> {
    let key_package: frost_core::keys::KeyPackage<C> = key_package.try_into()?;
    if !key_package.is_valid() {
        return Err(Error::General("Error signing, bad inputs".to_string()));
    }
    let signing_nonces: frost_core::round1::SigningNonces<C> = signing_nonce.try_into()?;
    if !signing_nonces.is_valid() {
        return Err(Error::General("Error signing, bad inputs".to_string()));
    }
    let signing_commitments_map =
        create_frost_signing_commitments_from_bytes::<C>(signing_commitments)?;
    if signing_commitments_map
        .iter()
        .any(|(i, c)| !i.is_valid() && !c.is_valid())
    {
        return Err(Error::General("Error signing, bad inputs".to_string()));
    }
    let signing_package = frost_core::SigningPackage::<C>::new(signing_commitments_map, message);
    let signature = frost_core::round2::sign::<C>(&signing_package, &signing_nonces, &key_package)
        .map_err(|_| Error::General("Error signing".to_string()))?;
    Ok(signature.into())
}

#[cfg(not(feature = "verify_only"))]
fn round1<C: Ciphersuite, R: CryptoRng + RngCore>(
    secret: &SigningShare,
    rng: &mut R,
) -> FrostResult<(SigningNonces, SigningCommitments)> {
    let signing_share: frost_core::keys::SigningShare<C> = secret.try_into()?;
    if !signing_share.is_valid() {
        return Err(Error::General(
            "Error: signing share is invalid".to_string(),
        ));
    }
    let (signing_nonces, signing_commitments) =
        frost_core::round1::commit::<C, R>(&signing_share, rng);
    Ok((signing_nonces.into(), signing_commitments.into()))
}

#[cfg(not(feature = "verify_only"))]
fn preprocess<C: Ciphersuite, R: CryptoRng + RngCore>(
    count: NonZeroU8,
    secret: &SigningShare,
    rng: &mut R,
) -> FrostResult<(Vec<SigningNonces>, Vec<SigningCommitments>)> {
    let signing_share: frost_core::keys::SigningShare<C> = secret.try_into()?;
    if !signing_share.is_valid() {
        return Err(Error::General(
            "Error: signing share is invalid".to_string(),
        ));
    }
    let (signing_nonces, signing_commitments) =
        frost_core::round1::preprocess::<C, R>(count.get(), &signing_share, rng);
    Ok((
        signing_nonces.iter().map(SigningNonces::from).collect(),
        signing_commitments
            .iter()
            .map(SigningCommitments::from)
            .collect(),
    ))
}

#[cfg(not(feature = "verify_only"))]
// #[cfg(test)]
fn generate_with_trusted_dealer<C: Ciphersuite, R: CryptoRng + RngCore>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut R,
) -> FrostResult<(BTreeMap<Identifier, SigningShare>, VerifyingKey)> {
    let (shares, public_package) = frost_core::keys::generate_with_dealer::<C, R>(
        max_signers,
        min_signers,
        frost_core::keys::IdentifierList::<C>::Default,
        rng,
    )
    .map_err(|_| Error::General("Error generating keys".to_string()))?;
    let shares = shares
        .iter()
        .map(|(id, share)| (id.into(), share.signing_share().into()))
        .collect();
    Ok((shares, public_package.verifying_key().into()))
}

fn create_frost_signing_commitments_from_bytes<C: Ciphersuite>(
    signing_commitments: &[(Identifier, SigningCommitments)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round1::SigningCommitments<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, commitment) in signing_commitments {
        signing_commitments_map.insert(index.try_into()?, commitment.try_into()?);
    }
    Ok(signing_commitments_map)
}

fn create_frost_signing_shares_from_bytes<C: Ciphersuite>(
    signing_shares: &[(Identifier, SignatureShare)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round2::SignatureShare<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, share) in signing_shares {
        signing_commitments_map.insert(index.try_into()?, share.try_into()?);
    }
    Ok(signing_commitments_map)
}

pub(crate) fn is_zero(value: &[u8]) -> subtle::Choice {
    let mut result = 0i8;
    for b in value {
        result |= *b as i8;
    }
    let result = ((result | -result) >> 7) + 1;
    subtle::Choice::from(result as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::Group as _;
    use frost_dkg::elliptic_curve_tools::SumOfProducts;
    use frost_dkg::{DkgResult, Parameters, Round, ScalarHash, SecretParticipant};
    use group::{Group, GroupEncoding};
    use rand_core::SeedableRng;
    use rstest::*;
    use std::num::{NonZeroU16, NonZeroUsize};
    use vsss_rs::IdentifierPrimeField;
    use vsss_rs::elliptic_curve::PrimeField;

    const DKG_MSG: &[u8] = b"test";

    #[test]
    fn sign_with_cheaters() {
        const THRESHOLD: u16 = 3;
        let scheme = Scheme::Ed25519Sha512;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
            .unwrap();
        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = scheme.signing_round1(secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id.clone(), (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (i, (id, (nonces, secret_share))) in signing_package.iter().enumerate() {
            let res = scheme.signing_round2(
                DKG_MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: (*secret_share).clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(THRESHOLD).unwrap(),
                },
            );
            let mut signature = res.unwrap();
            if i & 1 == 1 {
                signature.value.iter_mut().for_each(|b| *b = 1);
            }
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
        }

        let res = scheme.aggregate(
            DKG_MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            Error::Cheaters(cheaters) => {
                // The new frost_core API only reports one culprit at a time
                assert_eq!(cheaters.len(), 1);
            }
            e => assert!(false, "Unexpected error: {:?}", e),
        }
    }

    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512, 32)]
    #[case::ed448(Scheme::Ed448Shake256, 57)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512, 32)]
    #[case::k256(Scheme::K256Sha256, 32)]
    #[case::p256(Scheme::P256Sha256, 32)]
    #[case::p384(Scheme::P384Sha384, 48)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512, 32)]
    #[case::taproot(Scheme::K256Taproot, 32)]
    #[case::reddecaf377(Scheme::RedDecaf377Blake2b512, 32)]
    #[case::redpallas(Scheme::RedPallasBlake2b512, 32)]
    #[case::schnorrkel(Scheme::SchnorrkelSubstrate, 32)]
    fn pregenerate(#[case] scheme: Scheme, #[case] length: usize) {
        let mut rng = rand::rngs::OsRng;
        let mut secret = SigningShare {
            scheme,
            value: vec![1u8; length],
        };
        // Clear the high bits
        secret.value[length - 1] = 0;
        secret.value[length - 2] = 0;
        let (signing_nonces, signing_commitments) = scheme
            .pregenerate_signing_nonces(NonZeroU8::new(200).unwrap(), &secret, &mut rng)
            .unwrap();
        assert_eq!(signing_nonces.len(), 200);
        assert_eq!(signing_commitments.len(), 200);
    }

    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512)]
    #[case::ed448(Scheme::Ed448Shake256)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512)]
    #[case::k256(Scheme::K256Sha256)]
    #[case::p256(Scheme::P256Sha256)]
    #[case::p384(Scheme::P384Sha384)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512)]
    #[case::taproot(Scheme::K256Taproot)]
    #[case::reddecaf377(Scheme::RedDecaf377Blake2b512)]
    #[case::redpallas(Scheme::RedPallasBlake2b512)]
    #[case::schnorrkel(Scheme::SchnorrkelSubstrate)]
    fn rounds(#[case] scheme: Scheme) {
        const MSG: &[u8] = b"test";
        const THRESHOLD: u16 = 3;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
            .unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = scheme.signing_round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id.clone(), (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = scheme.signing_round2(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(THRESHOLD).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
        }

        let res = scheme.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        assert!(res.is_ok());
    }

    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512)]
    #[case::ed448(Scheme::Ed448Shake256)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512)]
    #[case::k256(Scheme::K256Sha256)]
    #[case::p256(Scheme::P256Sha256)]
    #[case::p384(Scheme::P384Sha384)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512)]
    #[case::taproot(Scheme::K256Taproot)]
    #[case::reddecaf377(Scheme::RedDecaf377Blake2b512)]
    #[case::redpallas(Scheme::RedPallasBlake2b512)]
    #[case::schnorrkel(Scheme::SchnorrkelSubstrate)]
    fn full(#[case] scheme: Scheme) {
        const MSG: &[u8] = b"test";
        const THRESHOLD: u16 = 3;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
            .unwrap();

        let mut signing_package = Vec::new();
        for (id, secret_share) in secret_shares {
            let res = scheme.pregenerate_signing_nonces(
                NonZeroU8::new(20).unwrap(),
                &secret_share,
                &mut rng,
            );
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.push((id, secret_share, nonces, commitments));
        }

        while signing_package[0].2.len() > 0 {
            let mut signing_commitments = Vec::new();
            let mut new_signing_package = Vec::new();
            for i in 0..signing_package.len() {
                signing_commitments.push((
                    signing_package[i].0.clone(),
                    signing_package[i].3.pop().unwrap(),
                ));
                new_signing_package.push((
                    signing_package[i].0.clone(),
                    signing_package[i].2.pop().unwrap(),
                    signing_package[i].1.clone(),
                ));
            }

            let mut verifying_shares = Vec::new();
            let mut signature_shares = Vec::new();
            for (id, nonces, secret_share) in new_signing_package {
                let res = scheme.signing_round2(
                    MSG,
                    &signing_commitments,
                    &nonces,
                    &KeyPackage {
                        identifier: id.clone(),
                        secret_share: secret_share.clone(),
                        verifying_key: verifying_key.clone(),
                        threshold: NonZeroU16::new(THRESHOLD).unwrap(),
                    },
                );
                assert!(res.is_ok());
                let signature = res.unwrap();
                signature_shares.push((id.clone(), signature));
                verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
            }

            let res = scheme.aggregate(
                MSG,
                &signing_commitments,
                &signature_shares,
                &verifying_shares,
                &verifying_key,
            );
            assert!(res.is_ok());
        }
    }

    // verify that the threshold of 2 is enough to sign a message
    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512)]
    #[case::ed448(Scheme::Ed448Shake256)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512)]
    #[case::k256(Scheme::K256Sha256)]
    #[case::p256(Scheme::P256Sha256)]
    #[case::p384(Scheme::P384Sha384)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512)]
    #[case::taproot(Scheme::K256Taproot)]
    #[case::reddecaf377(Scheme::RedDecaf377Blake2b512)]
    #[case::redpallas(Scheme::RedPallasBlake2b512)]
    #[case::schnorrkel(Scheme::SchnorrkelSubstrate)]
    fn min_threshold(#[case] scheme: Scheme) {
        const MSG: &[u8] = b"test";
        const THRESHOLD: u16 = 2;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 2, &mut rng)
            .unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = scheme.signing_round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id.clone(), (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = scheme.signing_round2(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(THRESHOLD).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
        }

        let res = scheme.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        assert!(res.is_ok());
    }

    fn dkg_core<G>(scheme: Scheme, generator: Option<G>) -> (VerifyingKey, Signature)
    where
        G: GroupEncoding + Group + Default + SumOfProducts,
        G::Scalar: ScalarHash,
    {
        let threshold: usize = 2;
        let limit: usize = 3;

        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let params = Parameters::<G>::new(
            NonZeroUsize::new(threshold).unwrap(),
            NonZeroUsize::new(limit).unwrap(),
            generator,
            None,
        );
        let mut secret_participants = [
            SecretParticipant::new_secret(IdentifierPrimeField(G::Scalar::from(1u64)), &params)
                .unwrap(),
            SecretParticipant::new_secret(IdentifierPrimeField(G::Scalar::from(2u64)), &params)
                .unwrap(),
            SecretParticipant::new_secret(IdentifierPrimeField(G::Scalar::from(3u64)), &params)
                .unwrap(),
        ];

        fn next_round<G>(participants: &mut [SecretParticipant<G>]) -> DkgResult<()>
        where
            G: GroupEncoding + Group + Default + SumOfProducts,
            G::Scalar: ScalarHash,
        {
            let mut round_generators = Vec::with_capacity(participants.len());

            for p in participants.iter_mut() {
                let round_generator = p.run()?;
                round_generators.push(round_generator);
            }

            for generator in &round_generators {
                for data in generator.iter() {
                    let p = &mut participants[data.dst_ordinal];
                    assert_eq!(data.dst_ordinal, p.get_ordinal());
                    assert_eq!(data.dst_id, p.get_id());
                    assert!(p.receive(data.data.as_slice()).is_ok());
                }
            }
            Ok(())
        }

        for _ in [Round::One, Round::Two, Round::Three] {
            let res = next_round(&mut secret_participants);
            assert!(res.is_ok());
        }

        let id1 = Identifier::from((scheme, 1u8));
        let id2 = Identifier::from((scheme, 2u8));
        let id3 = Identifier::from((scheme, 3u8));

        let pk = secret_participants[0].get_public_key().unwrap();

        let verifying_key = VerifyingKey {
            scheme,
            value: pk.to_bytes().as_ref().to_vec(),
        };
        let mut secret_shares = BTreeMap::new();

        secret_shares.insert(
            id1,
            SigningShare {
                scheme,
                value: secret_participants[0]
                    .get_secret_share()
                    .unwrap()
                    .value
                    .0
                    .to_repr()
                    .as_ref()
                    .to_vec(),
            },
        );
        secret_shares.insert(
            id2,
            SigningShare {
                scheme,
                value: secret_participants[1]
                    .get_secret_share()
                    .unwrap()
                    .value
                    .0
                    .to_repr()
                    .as_ref()
                    .to_vec(),
            },
        );
        secret_shares.insert(
            id3,
            SigningShare {
                scheme,
                value: secret_participants[2]
                    .get_secret_share()
                    .unwrap()
                    .value
                    .0
                    .to_repr()
                    .as_ref()
                    .to_vec(),
            },
        );

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in &secret_shares {
            let res = scheme.signing_round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id.clone(), (nonces, secret_share));
            signing_commitments.push((id.clone(), commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = scheme.signing_round2(
                DKG_MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU16::new(threshold as u16).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
        }

        let res = scheme.aggregate(
            DKG_MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        assert!(res.is_ok());
        let signature = res.unwrap();
        (verifying_key, signature)
    }

    #[test]
    fn dkg_k256_taproot() {
        let (verifying_key, signature) =
            dkg_core::<k256::ProjectivePoint>(Scheme::K256Taproot, None);

        let res = Scheme::K256Taproot.verify(DKG_MSG, &verifying_key, &signature);
        assert!(res.is_ok());
        let verifying_key: k256::schnorr::VerifyingKey = verifying_key.try_into().unwrap();
        let signature: k256::schnorr::Signature = signature.try_into().unwrap();
        let msg = Sha256::digest(DKG_MSG);
        assert!(verifying_key.verify_raw(&msg, &signature).is_ok());
    }

    #[test]
    fn dkg_jubjub() {
        let (verifying_key, signature) = dkg_core::<jubjub::SubgroupPoint>(
            Scheme::RedJubjubBlake2b512,
            Some(frost_redjubjub::JubjubGroup::generator()),
        );

        // Orchard uses the pasta curves not jubjub
        let verifying_key: reddsa::VerificationKey<reddsa::sapling::SpendAuth> =
            verifying_key.try_into().unwrap();
        let signature: reddsa::Signature<reddsa::sapling::SpendAuth> =
            signature.try_into().unwrap();
        assert!(verifying_key.verify(DKG_MSG, &signature).is_ok());
    }

    #[test]
    fn dkg_pallas() {
        let (verifying_key, signature) = dkg_core::<pallas::Point>(
            Scheme::RedPallasBlake2b512,
            Some(frost_redpallas::PallasGroup::generator()),
        );

        // Orchard uses the pasta curves not jubjub
        let verifying_key: reddsa::VerificationKey<reddsa::orchard::SpendAuth> =
            verifying_key.try_into().unwrap();
        let signature: reddsa::Signature<reddsa::orchard::SpendAuth> =
            signature.try_into().unwrap();
        assert!(verifying_key.verify(DKG_MSG, &signature).is_ok());
    }

    #[test]
    fn dkg_decaf377() {
        let (verifying_key, signature) =
            dkg_core::<decaf377::Element>(Scheme::RedDecaf377Blake2b512, None);

        let pk: decaf377_rdsa::VerificationKey<decaf377_rdsa::SpendAuth> =
            verifying_key.try_into().unwrap();
        let sg: decaf377_rdsa::Signature<decaf377_rdsa::SpendAuth> = signature.try_into().unwrap();
        assert!(pk.verify(DKG_MSG, &sg).is_ok());
    }

    #[test]
    fn dkg_schnorrkel() {
        let (verifying_key, signature) =
            dkg_core::<curve25519::WrappedRistretto>(Scheme::SchnorrkelSubstrate, None);

        let res = Scheme::SchnorrkelSubstrate.verify(DKG_MSG, &verifying_key, &signature);
        assert!(res.is_ok());
        let pk: schnorrkel::PublicKey = verifying_key.try_into().unwrap();
        let sg: schnorrkel::Signature = signature.try_into().unwrap();
        assert!(pk.verify_simple(b"substrate", DKG_MSG, &sg).is_ok());
    }
}
