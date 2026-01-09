//! Methods for combining signatures from LIT

use crate::{SdkError, SdkResult};
use ecdsa::{
    EncodedPoint, RecoveryId,
    hazmat::{DigestPrimitive, VerifyPrimitive},
    signature::hazmat::PrehashVerifier,
};
use elliptic_curve_tools::{group, prime_field};
use lit_node_core::{
    CompressedBytes, CompressedHex, CurveType, EcdsaSignedMessageShare, KeyFormatPreference,
    PeerId, SignableOutput, SigningAlgorithm, SigningScheme,
    hd_keys_curves_wasm::{HDDerivable, HDDeriver},
    lit_rust_crypto::{
        blsful::{self, Bls12381G2Impl, PublicKey, Signature},
        decaf377, ed448_goldilocks,
        elliptic_curve::{
            self, Curve, CurveArithmetic, Field, FieldBytesSize, PrimeCurve, ScalarPrimitive,
            generic_array::ArrayLength,
            ops::Reduce,
            pkcs8::AssociatedOid,
            point::{AffineCoordinates, DecompressPoint, PointCompression},
            sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        },
        group::GroupEncoding,
        jubjub, k256, p256, p384, pallas, vsss_rs,
    },
};

use lit_node_core::ethers::utils::keccak256;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::ops::Add;

/// An ecdsa signature share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaSignatureShare<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C::ProjectivePoint: GroupEncoding,
    C::Scalar: HDDeriver,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
{
    /// The signature `r` component
    #[serde(with = "group")]
    pub r: C::ProjectivePoint,
    /// The signature `s` component
    #[serde(with = "prime_field")]
    pub s: C::Scalar,
}

impl<C> EcdsaSignatureShare<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C::ProjectivePoint: GroupEncoding,
    C::Scalar: HDDeriver,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
{
    /// Combine the signature shares into a signature
    /// Verify should be called after wards to check everything
    pub fn combine_into_signature(
        shares: &[EcdsaSignatureShare<C>],
    ) -> SdkResult<EcdsaFullSignature<C>> {
        // Ensure non-empty shares
        if shares.is_empty() {
            return Err(SdkError::SignatureCombine(
                "No shares were supplied".to_string(),
            ));
        }
        // Check that all signature shares have the same r
        if shares[1..].iter().any(|s| s.r != shares[0].r) {
            return Err(SdkError::SignatureCombine(
                "Incompatible signature shares".to_string(),
            ));
        }
        let sig_s = shares.iter().fold(C::Scalar::ZERO, |acc, s| acc + s.s);

        Ok(EcdsaFullSignature {
            r: shares[0].r,
            s: sig_s,
        })
    }
}

/// A full ecdsa signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaFullSignature<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C::ProjectivePoint: GroupEncoding,
    C::Scalar: HDDeriver,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
{
    /// The signature `r` component
    #[serde(with = "group")]
    pub r: C::ProjectivePoint,
    /// The signature `s` component
    #[serde(with = "prime_field")]
    pub s: C::Scalar,
}

impl<C> TryFrom<EcdsaFullSignature<C>> for ecdsa::Signature<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C::ProjectivePoint: GroupEncoding,
    C::Scalar: HDDeriver,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
{
    type Error = SdkError;

    fn try_from(value: EcdsaFullSignature<C>) -> SdkResult<Self> {
        let r = x_coordinate::<C>(&value.r);
        let r = <C::Scalar as Into<ScalarPrimitive<C>>>::into(r);
        let s = <C::Scalar as Into<ScalarPrimitive<C>>>::into(value.s);
        // from_scalars checks that both r and s are not zero
        let signature = ecdsa::Signature::<C>::from_scalars(r.to_bytes(), s.to_bytes())?;
        match signature.normalize_s() {
            Some(normalized) => Ok(normalized),
            None => Ok(signature),
        }
    }
}

/// The resulting combined signature output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDataOutput {
    /// The serialized signature
    pub signature: String,
    /// The public key
    pub verifying_key: String,
    /// The signed data
    pub signed_data: String,
    /// The recovery id if ECDSA
    pub recovery_id: Option<u8>,
}

/// Attempts to combine the signature shares.
/// If the resulting combined signature is valid, returns the combined signature.
/// Otherwise, returns an error.
///
/// It does not distinguish between different types of signatures (e.g., ECDSA, BLS, etc.)
/// and will return the first valid signature it finds in the following order
///
/// 1. Frost
/// 2. BLS
/// 3. ECDSA
pub fn combine_and_verify_signature_shares(
    signature_shares: &[SignableOutput],
) -> SdkResult<SignedDataOutput> {
    let mut bls_signing_package = Vec::with_capacity(signature_shares.len());
    let mut frost_signing_package = Vec::with_capacity(signature_shares.len());
    let mut ecdsa_signing_package =
        Vec::<EcdsaSignedMessageShare>::with_capacity(signature_shares.len());

    for signature_share in signature_shares {
        match signature_share {
            SignableOutput::EcdsaSignedMessageShare(ecdsa_msg_share) => {
                if ecdsa_msg_share.result == "success" {
                    ecdsa_signing_package.push(ecdsa_msg_share.clone());
                }
            }
            SignableOutput::BlsSignedMessageShare(bls_msg_share) => {
                if bls_msg_share.result == "success" {
                    let identifier: blsful::inner_types::Scalar =
                        serde_json::from_str(&bls_msg_share.share_id)?;
                    let signature_share: blsful::SignatureShare<Bls12381G2Impl> =
                        serde_json::from_str(&bls_msg_share.signature_share)?;
                    let verifying_share: blsful::PublicKeyShare<Bls12381G2Impl> =
                        serde_json::from_str(&bls_msg_share.verifying_share)?;
                    let public_key: PublicKey<Bls12381G2Impl> =
                        serde_json::from_str(&bls_msg_share.public_key)?;
                    let message = hex::decode(&bls_msg_share.message)?;
                    bls_signing_package.push((
                        identifier,
                        signature_share,
                        verifying_share,
                        public_key,
                        message,
                        bls_msg_share.peer_id.clone(),
                    ));
                }
            }
            SignableOutput::FrostSignedMessageShare(frost_msg_share) => {
                if frost_msg_share.result == "success" {
                    let identifier: lit_frost::Identifier =
                        serde_json::from_str(&frost_msg_share.share_id)?;
                    let signature_share: lit_frost::SignatureShare =
                        serde_json::from_str(&frost_msg_share.signature_share)?;
                    let verifying_share: lit_frost::VerifyingShare =
                        serde_json::from_str(&frost_msg_share.verifying_share)?;
                    let public_key: lit_frost::VerifyingKey =
                        serde_json::from_str(&frost_msg_share.public_key)?;
                    let signing_commitments: lit_frost::SigningCommitments =
                        serde_json::from_str(&frost_msg_share.signing_commitments)?;
                    let signing_scheme = frost_msg_share.sig_type.parse::<SigningScheme>()?;
                    let scheme = signing_scheme_to_frost_scheme(signing_scheme)?;
                    let message = hex::decode(&frost_msg_share.message)?;
                    frost_signing_package.push((
                        identifier,
                        signature_share,
                        verifying_share,
                        public_key,
                        signing_commitments,
                        scheme,
                        message,
                        frost_msg_share.peer_id.clone(),
                    ));
                }
            }
        }
    }

    if frost_signing_package.len() > 1 {
        let first_entry = &frost_signing_package[0];
        let mut signature_shares = Vec::with_capacity(frost_signing_package.len());
        let mut verifying_shares = Vec::with_capacity(frost_signing_package.len());
        let mut signing_commitments = Vec::with_capacity(frost_signing_package.len());

        signature_shares.push((first_entry.0.clone(), first_entry.1.clone()));
        verifying_shares.push((first_entry.0.clone(), first_entry.2.clone()));
        signing_commitments.push((first_entry.0.clone(), first_entry.4.clone()));

        for entry in &frost_signing_package[1..] {
            debug_assert_eq!(
                first_entry.3, entry.3,
                "frost public keys do not match: {}, {}",
                first_entry.2, entry.2
            );
            debug_assert_eq!(
                first_entry.5, entry.5,
                "frost signing schemes do not match: {}, {}",
                first_entry.4, entry.4
            );
            debug_assert_eq!(
                first_entry.6,
                entry.6,
                "frost messages do not match: {}, {}",
                hex::encode(&first_entry.6),
                hex::encode(&entry.6)
            );
            signature_shares.push((entry.0.clone(), entry.1.clone()));
            verifying_shares.push((entry.0.clone(), entry.2.clone()));
            signing_commitments.push((entry.0.clone(), entry.4.clone()));
        }
        let res = first_entry.5.aggregate(
            &first_entry.6,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &first_entry.3,
        );
        return if res.is_err() {
            let e = res.expect_err("frost signature from shares is invalid");
            match e {
                lit_frost::Error::Cheaters(cheaters) => {
                    let mut cheater_peer_ids = Vec::with_capacity(cheaters.len());
                    for cheater in cheaters {
                        let found = frost_signing_package
                            .iter()
                            .find(|p| p.0 == cheater)
                            .map(|cheater| cheater.7.clone());
                        if let Some(peer_id) = found {
                            cheater_peer_ids.push(peer_id);
                        }
                    }
                    Err(SdkError::SignatureCombine(format!(
                        "frost signature from shares is invalid. Invalid share peer ids: {}",
                        cheater_peer_ids.join(", ")
                    )))
                }
                _ => Err(SdkError::SignatureCombine(e.to_string())),
            }
        } else {
            Ok(SignedDataOutput {
                signature: serde_json::to_string(
                    &res.expect("frost signature from shares is valid"),
                )?,
                verifying_key: serde_json::to_string(&first_entry.3)?,
                signed_data: hex::encode(&first_entry.6),
                recovery_id: None,
            })
        };
    }
    if bls_signing_package.len() > 1 {
        let first_entry = &bls_signing_package[0];
        let mut signature_shares = Vec::with_capacity(bls_signing_package.len());
        let mut verifying_shares = Vec::with_capacity(bls_signing_package.len());

        signature_shares.push(first_entry.1);
        verifying_shares.push((first_entry.0, first_entry.5.clone(), first_entry.2));
        for entry in &bls_signing_package[1..] {
            debug_assert_eq!(
                first_entry.3, entry.3,
                "bls public keys do not match: {}, {}",
                first_entry.2, entry.2
            );
            debug_assert_eq!(
                first_entry.4,
                entry.4,
                "bls messages do not match: {}, {}",
                hex::encode(&first_entry.4),
                hex::encode(&entry.4)
            );
            signature_shares.push(entry.1);
            verifying_shares.push((entry.0, entry.5.clone(), entry.2));
        }
        let public_key = first_entry.3;
        let signature = Signature::<Bls12381G2Impl>::from_shares(&signature_shares)
            .expect("bls signature from shares");
        if signature.verify(&public_key, &first_entry.4).is_err() {
            // Identify which shares are invalid
            let mut invalid_shares = Vec::with_capacity(signature_shares.len());
            for (share, (_identifier, peer_id, verifier)) in
                signature_shares.iter().zip(verifying_shares.iter())
            {
                if share.verify(verifier, &first_entry.4).is_err() {
                    invalid_shares.push(peer_id.clone());
                }
            }
            return Err(SdkError::SignatureCombine(format!(
                "bls signature from shares is invalid. Invalid share peer ids: {}",
                invalid_shares.join(", ")
            )));
        }
        return Ok(SignedDataOutput {
            signature: serde_json::to_string(&signature)?,
            verifying_key: public_key.0.to_compressed_hex(),
            signed_data: hex::encode(&first_entry.4),
            recovery_id: None,
        });
    }
    if ecdsa_signing_package.len() > 1 {
        let signing_scheme = ecdsa_signing_package[0].sig_type.parse::<SigningScheme>()?;
        match signing_scheme {
            SigningScheme::EcdsaK256Sha256 => {
                return verify_ecdsa_signing_package::<k256::Secp256k1>(&ecdsa_signing_package);
            }
            SigningScheme::EcdsaP256Sha256 => {
                return verify_ecdsa_signing_package::<p256::NistP256>(&ecdsa_signing_package);
            }
            SigningScheme::EcdsaP384Sha384 => {
                return verify_ecdsa_signing_package::<p384::NistP384>(&ecdsa_signing_package);
            }
            _ => {}
        }
    }

    Err(SdkError::SignatureCombine(
        "no valid signature shares found".to_string(),
    ))
}

/// Verify ECDSA signature shares
pub fn verify_ecdsa_signing_package<C>(
    shares: &[EcdsaSignedMessageShare],
) -> SdkResult<SignedDataOutput>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + AssociatedOid + PointCompression,
    C::ProjectivePoint: GroupEncoding + HDDerivable,
    C::AffinePoint: DeserializeOwned
        + FromEncodedPoint<C>
        + ToEncodedPoint<C>
        + VerifyPrimitive<C>
        + DecompressPoint<C>,
    C::Scalar: HDDeriver + From<PeerId> + DeserializeOwned,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let mut sig_shares = Vec::<EcdsaSignatureShare<C>>::with_capacity(shares.len());
    let first_share = &shares[0];
    sig_shares.push(EcdsaSignatureShare {
        r: C::ProjectivePoint::from(serde_json::from_str::<C::AffinePoint>(&first_share.big_r)?),
        s: serde_json::from_str(&first_share.signature_share)?,
    });
    for share in &shares[1..] {
        debug_assert_eq!(first_share.public_key, share.public_key);
        debug_assert_eq!(first_share.digest, share.digest);
        debug_assert_eq!(first_share.big_r, share.big_r);
        debug_assert_eq!(first_share.sig_type, share.sig_type);

        sig_shares.push(EcdsaSignatureShare {
            r: C::ProjectivePoint::from(serde_json::from_str::<C::AffinePoint>(&share.big_r)?),
            s: serde_json::from_str(&share.signature_share)?,
        });
    }
    let initial_public_key: String =
        serde_json::from_str(&first_share.public_key).expect("public key");
    let public_key = hex::decode(&initial_public_key)?;
    let public_key = EncodedPoint::<C>::from_bytes(&public_key)
        .map_err(|_| SdkError::SignatureCombine("invalid public key".to_string()))?;
    let public_key_affine = Option::from(C::AffinePoint::from_encoded_point(&public_key))
        .ok_or_else(|| SdkError::SignatureCombine("invalid public key".to_string()))?;
    let signature =
        EcdsaSignatureShare::<C>::combine_into_signature(&sig_shares).expect("signature");

    let message = hex::decode(&first_share.digest)?;
    let vk = ecdsa::VerifyingKey::<C>::from_affine(public_key_affine).expect("verifying key");
    let signature: ecdsa::Signature<C> = signature.try_into().expect("signature");
    <ecdsa::VerifyingKey<C> as PrehashVerifier<ecdsa::Signature<C>>>::verify_prehash(
        &vk, &message, &signature,
    )?;

    let rid = RecoveryId::trial_recovery_from_prehash(&vk, &message, &signature)?;

    Ok(SignedDataOutput {
        signature: serde_json::to_string(&signature)?,
        verifying_key: initial_public_key,
        signed_data: shares[0].digest.clone(),
        recovery_id: Some(rid.to_byte()),
    })
}

/// Verify a signature returned from lit-node
pub fn verify_signature(
    signing_scheme: SigningScheme,
    package: &SignedDataOutput,
) -> SdkResult<()> {
    match signing_scheme {
        SigningScheme::EcdsaK256Sha256 => verify_ecdsa_signature::<k256::Secp256k1>(package),
        SigningScheme::EcdsaP256Sha256 => verify_ecdsa_signature::<p256::NistP256>(package),
        SigningScheme::EcdsaP384Sha384 => verify_ecdsa_signature::<p384::NistP384>(package),
        SigningScheme::SchnorrEd25519Sha512
        | SigningScheme::SchnorrRistretto25519Sha512
        | SigningScheme::SchnorrK256Sha256
        | SigningScheme::SchnorrP256Sha256
        | SigningScheme::SchnorrP384Sha384
        | SigningScheme::SchnorrK256Taproot
        | SigningScheme::SchnorrEd448Shake256
        | SigningScheme::SchnorrRedJubjubBlake2b512
        | SigningScheme::SchnorrRedPallasBlake2b512
        | SigningScheme::SchnorrRedDecaf377Blake2b512
        | SigningScheme::SchnorrkelSubstrate => {
            let scheme = signing_scheme_to_frost_scheme(signing_scheme)?;
            let signature = serde_json::from_str::<lit_frost::Signature>(&package.signature)?;
            let public_key =
                serde_json::from_str::<lit_frost::VerifyingKey>(&package.verifying_key)?;
            let message = hex::decode(&package.signed_data)?;
            scheme
                .verify(&message, &public_key, &signature)
                .map_err(|_| SdkError::SignatureVerify)
        }
        SigningScheme::Bls12381G1ProofOfPossession | SigningScheme::Bls12381 => {
            let public_key: PublicKey<Bls12381G2Impl> =
                serde_json::from_str(&format!("\"{}\"", &package.verifying_key))?;
            let signature: Signature<Bls12381G2Impl> = serde_json::from_str(&package.signature)?;
            let message = hex::decode(&package.signed_data)?;
            signature.verify(&public_key, &message)?;
            Ok(())
        }
    }
}

/// Convert the signing_scheme to a frost scheme
pub fn signing_scheme_to_frost_scheme(value: SigningScheme) -> SdkResult<lit_frost::Scheme> {
    match value {
        SigningScheme::Bls12381 | SigningScheme::Bls12381G1ProofOfPossession => Err(
            SdkError::Parse("BLS signatures are not supported by FROST".to_string()),
        ),
        SigningScheme::EcdsaK256Sha256
        | SigningScheme::EcdsaP256Sha256
        | SigningScheme::EcdsaP384Sha384 => Err(SdkError::Parse(
            "ECDSA signatures are not supported by FROST".to_string(),
        )),
        SigningScheme::SchnorrEd25519Sha512 => Ok(lit_frost::Scheme::Ed25519Sha512),
        SigningScheme::SchnorrK256Sha256 => Ok(lit_frost::Scheme::K256Sha256),
        SigningScheme::SchnorrP256Sha256 => Ok(lit_frost::Scheme::P256Sha256),
        SigningScheme::SchnorrP384Sha384 => Ok(lit_frost::Scheme::P384Sha384),
        SigningScheme::SchnorrRistretto25519Sha512 => Ok(lit_frost::Scheme::Ristretto25519Sha512),
        SigningScheme::SchnorrEd448Shake256 => Ok(lit_frost::Scheme::Ed448Shake256),
        SigningScheme::SchnorrRedJubjubBlake2b512 => Ok(lit_frost::Scheme::RedJubjubBlake2b512),
        SigningScheme::SchnorrRedPallasBlake2b512 => Ok(lit_frost::Scheme::RedPallasBlake2b512),
        SigningScheme::SchnorrK256Taproot => Ok(lit_frost::Scheme::K256Taproot),
        SigningScheme::SchnorrRedDecaf377Blake2b512 => Ok(lit_frost::Scheme::RedDecaf377Blake2b512),
        SigningScheme::SchnorrkelSubstrate => Ok(lit_frost::Scheme::SchnorrkelSubstrate),
    }
}

/// Verify an ecdsa signature
pub fn verify_ecdsa_signature<C>(package: &SignedDataOutput) -> SdkResult<()>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + AssociatedOid + PointCompression,
    C::ProjectivePoint: GroupEncoding + HDDerivable,
    C::AffinePoint: DeserializeOwned
        + FromEncodedPoint<C>
        + ToEncodedPoint<C>
        + VerifyPrimitive<C>
        + DecompressPoint<C>,
    C::Scalar: HDDeriver + From<PeerId> + DeserializeOwned,
    <FieldBytesSize<C> as Add>::Output: ArrayLength<u8>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let message = hex::decode(&package.signed_data)?;
    let public_key = hex::decode(&package.verifying_key)?;
    let public_key = EncodedPoint::<C>::from_bytes(&public_key)
        .map_err(|_| SdkError::SignatureCombine("invalid public key".to_string()))?;
    let public_key_affine = Option::from(C::AffinePoint::from_encoded_point(&public_key))
        .ok_or_else(|| SdkError::SignatureCombine("invalid public key".to_string()))?;
    let vk = ecdsa::VerifyingKey::<C>::from_affine(public_key_affine).expect("verifying key");
    let signature = serde_json::from_str::<ecdsa::Signature<C>>(&package.signature)?;
    <ecdsa::VerifyingKey<C> as PrehashVerifier<ecdsa::Signature<C>>>::verify_prehash(
        &vk, &message, &signature,
    )?;
    Ok(())
}

pub(crate) fn x_coordinate<C>(point: &C::ProjectivePoint) -> C::Scalar
where
    C: PrimeCurve + CurveArithmetic,
{
    use elliptic_curve::group::Curve as _;

    let pt = point.to_affine();
    <C::Scalar as Reduce<<C as Curve>::Uint>>::reduce_bytes(&pt.x())
}

/// Derive the public key given the signing scheme, tweak key id and root keys
pub fn get_derived_public_key(
    signing_scheme: SigningScheme,
    key_id: &[u8],
    root_keys: &[String],
) -> SdkResult<String> {
    match signing_scheme.curve_type() {
        CurveType::BLS | CurveType::BLS12381G1 => derive_public_key::<
            blsful::inner_types::G1Projective,
        >(signing_scheme, key_id, root_keys),
        CurveType::K256 => {
            derive_public_key::<k256::ProjectivePoint>(signing_scheme, key_id, root_keys)
        }
        CurveType::P256 => {
            derive_public_key::<p256::ProjectivePoint>(signing_scheme, key_id, root_keys)
        }
        CurveType::P384 => {
            derive_public_key::<p384::ProjectivePoint>(signing_scheme, key_id, root_keys)
        }
        CurveType::Ed25519 => derive_public_key::<vsss_rs::curve25519::WrappedEdwards>(
            signing_scheme,
            key_id,
            root_keys,
        ),
        CurveType::Ristretto25519 => derive_public_key::<vsss_rs::curve25519::WrappedRistretto>(
            signing_scheme,
            key_id,
            root_keys,
        ),
        CurveType::Ed448 => {
            derive_public_key::<ed448_goldilocks::EdwardsPoint>(signing_scheme, key_id, root_keys)
        }
        CurveType::RedJubjub => {
            derive_public_key::<jubjub::SubgroupPoint>(signing_scheme, key_id, root_keys)
        }
        CurveType::RedPallas => {
            derive_public_key::<pallas::Point>(signing_scheme, key_id, root_keys)
        }
        CurveType::RedDecaf377 => {
            derive_public_key::<decaf377::Element>(signing_scheme, key_id, root_keys)
        }
    }
}

fn derive_public_key<G>(
    signing_scheme: SigningScheme,
    key_id: &[u8],
    root_keys: &[String],
) -> SdkResult<String>
where
    G: HDDerivable + GroupEncoding + Default + CompressedBytes,
    G::Scalar: HDDeriver,
{
    let deriver = G::Scalar::create(key_id, signing_scheme.id_sign_ctx());
    let mut keys = Vec::with_capacity(root_keys.len());
    for rk in root_keys {
        let rk = G::from_compressed_hex(rk)
            .ok_or_else(|| SdkError::Parse("Invalid root key".to_string()))?;
        keys.push(rk);
    }
    let pk = deriver.hd_derive_public_key(&keys);

    if signing_scheme.supports_algorithm(SigningAlgorithm::Schnorr) {
        let pk = lit_frost::VerifyingKey {
            scheme: signing_scheme_to_frost_scheme(signing_scheme)?,
            value: pk.to_compressed(),
        };
        let pk = serde_json::to_string(&pk)?;
        Ok(pk)
    } else {
        Ok(match signing_scheme.preferred_format() {
            KeyFormatPreference::Compressed => pk.to_compressed_hex(),
            KeyFormatPreference::Uncompressed => pk.to_uncompressed_hex(),
        })
    }
}

/// Derive the lit action public key
pub fn get_lit_action_public_key(
    signing_scheme: SigningScheme,
    action_ipfs_id: &str,
    root_keys: &[String],
) -> SdkResult<String> {
    let key_id = keccak256(format!("lit_action_{}", action_ipfs_id));
    get_derived_public_key(signing_scheme, &key_id, root_keys)
}
