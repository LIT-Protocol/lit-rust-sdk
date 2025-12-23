use crate::error::LitSdkError;
use lit_sdk::lit_node_core::lit_rust_crypto::blsful::{
    self, inner_types::GroupEncoding, Bls12381G1Impl, Bls12381G2Impl, BlsSignatureImpl, Signature,
    SignatureShare,
};
use lit_sdk::lit_node_core::{
    BlsSignedMessageShare, EcdsaSignedMessageShare, FrostSignedMessageShare, SignableOutput,
};
use serde::de::DeserializeOwned;

/// Encrypt data with a BLS public key using time-lock encryption.
pub fn bls_encrypt(
    public_key_hex: &str,
    message: &[u8],
    identity: &[u8],
) -> Result<String, LitSdkError> {
    use base64ct::{Base64, Encoding};
    use blsful::{PublicKey, SignatureSchemes, TimeCryptCiphertext};

    let key_hex = public_key_hex.trim_start_matches("0x");

    // Parse the public key - G2 pubkeys are 96 hex chars (48 bytes)
    if key_hex.len() != 96 {
        return Err(LitSdkError::Crypto(format!(
            "invalid BLS public key length (expected 96 hex chars, got {})",
            key_hex.len()
        )));
    }

    let pk_bytes = hex::decode(key_hex).map_err(|e| LitSdkError::Crypto(e.to_string()))?;
    let pk = PublicKey::<Bls12381G2Impl>::try_from(pk_bytes.as_slice())
        .map_err(|e| LitSdkError::Crypto(format!("invalid BLS public key: {e}")))?;

    let ciphertext: TimeCryptCiphertext<Bls12381G2Impl> = pk
        .encrypt_time_lock(SignatureSchemes::ProofOfPossession, message, identity)
        .map_err(|e| LitSdkError::Crypto(format!("BLS encryption failed: {e}")))?;

    let ct_bytes: Vec<u8> = ciphertext.into();
    Ok(Base64::encode_string(&ct_bytes))
}

/// Verify BLS signature shares and decrypt ciphertext.
pub fn bls_verify_and_decrypt_with_signature_shares(
    public_key_hex: &str,
    identity: &[u8],
    ciphertext_base64: &str,
    shares_json: &[String],
) -> Result<Vec<u8>, LitSdkError> {
    use base64ct::{Base64, Encoding};

    let key_hex = public_key_hex.trim_start_matches("0x");
    let ciphertext_bytes =
        Base64::decode_vec(ciphertext_base64).map_err(|e| LitSdkError::Crypto(e.to_string()))?;

    // Match lit-bls-wasm behavior: G2 pubkeys are 96 hex chars, G1 are 192.
    match key_hex.len() {
        96 => verify_and_decrypt_inner::<Bls12381G2Impl>(
            key_hex,
            identity,
            &ciphertext_bytes,
            shares_json,
        ),
        192 => verify_and_decrypt_inner::<Bls12381G1Impl>(
            key_hex,
            identity,
            &ciphertext_bytes,
            shares_json,
        ),
        other => Err(LitSdkError::Crypto(format!(
            "invalid BLS public key length (expected 96 or 192 hex chars, got {other})"
        ))),
    }
}

fn verify_and_decrypt_inner<C>(
    key_hex: &str,
    identity: &[u8],
    ciphertext_bytes: &[u8],
    shares_json: &[String],
) -> Result<Vec<u8>, LitSdkError>
where
    C: BlsSignatureImpl + DeserializeOwned,
{
    use blsful::{PublicKey, TimeCryptCiphertext};

    let pk_bytes = hex::decode(key_hex).map_err(|e| LitSdkError::Crypto(e.to_string()))?;
    let pk = PublicKey::<C>::try_from(pk_bytes.as_slice())
        .map_err(|_| LitSdkError::Crypto("invalid BLS public key".into()))?;

    let ciphertext = TimeCryptCiphertext::<C>::try_from(ciphertext_bytes)
        .map_err(|_| LitSdkError::Crypto("invalid ciphertext".into()))?;

    // Parse signature shares
    let mut signature_shares = Vec::with_capacity(shares_json.len());
    for share in shares_json {
        let parsed = serde_json::from_str::<SignatureShare<C>>(share)
            .map_err(|e| LitSdkError::Crypto(format!("failed to parse BLS share: {e}")))?;
        signature_shares.push(parsed);
    }

    // Combine shares into signature
    let signature = Signature::from_shares(&signature_shares)
        .map_err(|e| LitSdkError::Crypto(format!("failed to combine BLS shares: {e}")))?;

    // Verify signature
    signature
        .verify(&pk, identity)
        .map_err(|e| LitSdkError::Crypto(format!("BLS signature verification failed: {e}")))?;

    // Decrypt
    let plaintext = Option::<Vec<u8>>::from(ciphertext.decrypt(&signature))
        .ok_or_else(|| LitSdkError::Crypto("BLS decryption failed".into()))?;

    Ok(plaintext)
}

pub fn combine_bls_signature_shares(shares_json: &[String]) -> Result<String, LitSdkError> {
    if shares_json.len() < 2 {
        return Err(LitSdkError::Crypto(
            "at least two BLS signature shares are required".into(),
        ));
    }

    // Try G2 first (most common), then G1
    if let Ok(sig) = combine_signature_shares_inner::<Bls12381G2Impl>(shares_json) {
        return Ok(sig);
    }
    if let Ok(sig) = combine_signature_shares_inner::<Bls12381G1Impl>(shares_json) {
        return Ok(sig);
    }

    Err(LitSdkError::Crypto(
        "invalid or unsupported BLS signature share format".into(),
    ))
}

fn combine_signature_shares_inner<C>(shares: &[String]) -> Result<String, LitSdkError>
where
    C: BlsSignatureImpl + DeserializeOwned,
{
    let mut signature_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let parsed = serde_json::from_str::<SignatureShare<C>>(share)
            .map_err(|e| LitSdkError::Crypto(format!("failed to parse BLS share: {e}")))?;
        signature_shares.push(parsed);
    }

    let signature = Signature::from_shares(&signature_shares)
        .map_err(|e| LitSdkError::Crypto(format!("failed to combine BLS shares: {e}")))?;
    Ok(hex::encode(signature.as_raw_value().to_bytes()))
}

/// Combine and verify signature shares from node responses.
/// Takes JSON strings of signature share objects and returns the combined signature as JSON.
pub fn combine_and_verify(shares: Vec<String>) -> Result<String, LitSdkError> {
    if shares.is_empty() {
        return Err(LitSdkError::Crypto("no signature shares provided".into()));
    }

    // Parse each share to determine its type and convert to SignableOutput
    let mut signable_outputs = Vec::with_capacity(shares.len());
    for share in &shares {
        let output = parse_signable_output(share)?;
        signable_outputs.push(output);
    }

    // Use lit-sdk's signature combining
    let result = lit_sdk::signature::combine_and_verify_signature_shares(&signable_outputs)
        .map_err(|e| LitSdkError::Crypto(format!("signature combine/verify failed: {e}")))?;

    serde_json::to_string(&result).map_err(|e| LitSdkError::Crypto(e.to_string()))
}

fn parse_signable_output(share_json: &str) -> Result<SignableOutput, LitSdkError> {
    // Try parsing as each type to determine which it is
    // ECDSA shares have "big_r" field, BLS have "signature_share" with different format,
    // Frost has "signing_commitments"

    let v: serde_json::Value =
        serde_json::from_str(share_json).map_err(|e| LitSdkError::Crypto(e.to_string()))?;

    // Check for characteristic fields to determine type
    if v.get("signing_commitments").is_some() || v.get("signingCommitments").is_some() {
        // Frost/Schnorr signature share
        let frost: FrostSignedMessageShare =
            serde_json::from_str(share_json).map_err(|e| LitSdkError::Crypto(e.to_string()))?;
        Ok(SignableOutput::FrostSignedMessageShare(frost))
    } else if v.get("big_r").is_some() || v.get("bigR").is_some() {
        // ECDSA signature share
        let ecdsa: EcdsaSignedMessageShare =
            serde_json::from_str(share_json).map_err(|e| LitSdkError::Crypto(e.to_string()))?;
        Ok(SignableOutput::EcdsaSignedMessageShare(ecdsa))
    } else if v.get("signature_share").is_some() || v.get("signatureShare").is_some() {
        // BLS signature share
        let bls: BlsSignedMessageShare =
            serde_json::from_str(share_json).map_err(|e| LitSdkError::Crypto(e.to_string()))?;
        Ok(SignableOutput::BlsSignedMessageShare(bls))
    } else {
        Err(LitSdkError::Crypto(
            "unrecognized signature share format".into(),
        ))
    }
}
