//! Methods for combining signatures created from Cait-Sith

use super::signature::{EcdsaFullSignature, SignedDataOutput, x_coordinate};
use crate::{SdkError, SdkResult};
use ecdsa::{
    RecoveryId,
    elliptic_curve::{Group, scalar::IsHigh, subtle::ConditionallyNegatable},
};
use serde::Deserialize;

/// Cait-Sith shares
#[derive(Clone, Debug, Deserialize)]
pub struct SignedDataShare {
    /// The signature type
    pub sig_type: String,
    /// The hashed and reduced data signed
    pub data_signed: k256::Scalar,
    /// The signature share `s_i`
    pub signature_share: k256::Scalar,
    /// The share's index
    pub share_index: u32,
    /// The signature `R` value
    pub big_r: k256::AffinePoint,
    /// The public verifying key
    pub public_key: k256::AffinePoint,
    /// The signature name aka Cait-Sith
    pub sig_name: String,
}

/// Combine and verify signature shares from Cait-Sith
pub fn combine_and_verify_signature_shares(
    signature_shares: &[SignedDataShare],
) -> SdkResult<SignedDataOutput> {
    if signature_shares.is_empty() {
        return Err(SdkError::SignatureCombine(
            "Empty signature shares".to_string(),
        ));
    }
    if signature_shares.iter().skip(1).any(|sig_share| {
        sig_share.big_r != signature_shares[0].big_r
            || sig_share.public_key != signature_shares[0].public_key
            || sig_share.data_signed != signature_shares[0].data_signed
    }) {
        return Err(SdkError::SignatureCombine(
            "Incompatible signature shares".to_string(),
        ));
    }
    let mut s: k256::Scalar = signature_shares.iter().map(|s| s.signature_share).sum();
    s.conditional_negate(s.is_high());

    let big_r = k256::ProjectivePoint::from(signature_shares[0].big_r);
    let r = x_coordinate::<k256::Secp256k1>(&big_r);
    let z = signature_shares[0].data_signed;
    let public_key = k256::ProjectivePoint::from(signature_shares[0].public_key);

    // sR == zG * rY =
    // (z + rx/k) * k * G == zG + rxG =
    // (z + rx) G == (z + rx) G
    if (big_r * s - (public_key * r + k256::ProjectivePoint::GENERATOR * z))
        .is_identity()
        .into()
    {
        let vk =
            ecdsa::VerifyingKey::<k256::Secp256k1>::from_affine(signature_shares[0].public_key)
                .expect("verifying key");
        let signature = EcdsaFullSignature { r: big_r, s }
            .try_into()
            .expect("signature");
        let digest_bytes = signature_shares[0].data_signed.to_bytes();
        let rid = RecoveryId::trial_recovery_from_prehash(&vk, &digest_bytes, &signature)?;
        Ok(SignedDataOutput {
            signature: serde_json::to_string(&signature)?,
            verifying_key: serde_json::to_string(&vk)?,
            signed_data: hex::encode(digest_bytes),
            recovery_id: Some(rid.to_byte()),
        })
    } else {
        Err(SdkError::SignatureCombine("Invalid signature".to_string()))
    }
}
