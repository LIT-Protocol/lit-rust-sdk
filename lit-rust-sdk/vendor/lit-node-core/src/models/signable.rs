use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// The ECDSA signature shares
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EcdsaSignedMessageShare {
    pub digest: String,
    pub result: String,
    pub share_id: String,
    pub peer_id: String,
    pub signature_share: String,
    pub big_r: String,
    pub compressed_public_key: String,
    pub public_key: String,
    pub sig_type: String,
}

/// Frost / Schnorr signature shares
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FrostSignedMessageShare {
    pub message: String,
    pub result: String,
    pub share_id: String,
    pub peer_id: String,
    pub signature_share: String,
    pub signing_commitments: String,
    pub verifying_share: String,
    pub public_key: String,
    pub sig_type: String,
}

/// Bls signature shares
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlsSignedMessageShare {
    pub message: String,
    pub result: String,
    pub peer_id: String,
    pub share_id: String,
    pub signature_share: String,
    pub verifying_share: String,
    pub public_key: String,
    pub sig_type: String,
}

/// The output signature types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SignableOutput {
    /// Ecdsa signature shares
    EcdsaSignedMessageShare(EcdsaSignedMessageShare),
    /// Frost / Schnorr signature shares
    FrostSignedMessageShare(FrostSignedMessageShare),
    /// Bls signature shares
    BlsSignedMessageShare(BlsSignedMessageShare),
}

impl From<EcdsaSignedMessageShare> for SignableOutput {
    fn from(share: EcdsaSignedMessageShare) -> Self {
        SignableOutput::EcdsaSignedMessageShare(share)
    }
}

impl From<FrostSignedMessageShare> for SignableOutput {
    fn from(share: FrostSignedMessageShare) -> Self {
        SignableOutput::FrostSignedMessageShare(share)
    }
}

impl From<BlsSignedMessageShare> for SignableOutput {
    fn from(share: BlsSignedMessageShare) -> Self {
        SignableOutput::BlsSignedMessageShare(share)
    }
}

impl SignableOutput {
    /// The failed message type for ECDSA
    pub fn ecdsa_failed_message_share() -> Self {
        EcdsaSignedMessageShare {
            digest: "".to_string(),
            result: "fail".to_string(),
            signature_share: "".to_string(),
            share_id: "".to_string(),
            peer_id: "".to_string(),
            big_r: "".to_string(),
            compressed_public_key: "".to_string(),
            public_key: "".to_string(),
            sig_type: "".to_string(),
        }
        .into()
    }

    /// Extract an ECDSA signature share
    pub fn ecdsa_signed_message_share(&self) -> Result<EcdsaSignedMessageShare> {
        match self {
            SignableOutput::EcdsaSignedMessageShare(share) => Ok((*share).clone()),
            _ => Err(Error::InvalidType(
                "Invalid SignableOutput type".to_string(),
            )),
        }
    }

    /// Extract a Frost / Schnorr signature share
    pub fn frost_signed_message_share(&self) -> Result<FrostSignedMessageShare> {
        match self {
            SignableOutput::FrostSignedMessageShare(share) => Ok((*share).clone()),
            _ => Err(Error::InvalidType(
                "Invalid SignableOutput type".to_string(),
            )),
        }
    }

    /// Extract a BLS signature share
    pub fn bls_signed_message_share(&self) -> Result<BlsSignedMessageShare> {
        match self {
            SignableOutput::BlsSignedMessageShare(share) => Ok((*share).clone()),
            _ => Err(Error::InvalidType(
                "Invalid SignableOutput type".to_string(),
            )),
        }
    }
}
