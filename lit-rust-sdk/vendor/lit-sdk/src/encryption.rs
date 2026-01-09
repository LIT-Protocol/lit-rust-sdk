//! Encryption methods

use crate::{EncryptedMulticastRequest, EndpointRequest, Response, SdkError, SdkResult, UrlPrefix};
use lit_node_core::{
    lit_rust_crypto::blsful::{
        Bls12381G2Impl, PublicKey, Signature, SignatureSchemes, SignatureShare, TimeCryptCiphertext,
    },
    request::EncryptionSignRequest as InnerEncryptionSignRequest,
    response::{EncryptionSignResponse as InnerEncryptionSignResponse, GenericResponse},
};
use std::{collections::HashMap, marker::PhantomData};
use uuid::Uuid;

/// The response type for encryption sign requests
pub type EncryptionSignResponse = Response<GenericResponse<InnerEncryptionSignResponse>>;

/// The encryption sign request struct
pub type EncryptionSignRequest = EncryptedMulticastRequest<
    EncryptionSignRequestBuilder,
    InnerEncryptionSignRequest,
    GenericResponse<InnerEncryptionSignResponse>,
>;

encrypted_multicast_builder!(
    EncryptionSignRequestBuilder,
    InnerEncryptionSignRequest,
    GenericResponse<InnerEncryptionSignResponse>,
    "/web/encryption/sign/v2"
);

impl EncryptionSignRequestBuilder {
    /// Check that the inner request fields are set
    fn request_checks(&self) -> SdkResult<()> {
        Ok(())
    }
}

/// Time Lock Encryption
pub fn encrypt_time_lock(
    public_key: &PublicKey<Bls12381G2Impl>,
    message: &[u8],
    identity: &[u8],
) -> SdkResult<TimeCryptCiphertext<Bls12381G2Impl>> {
    let ciphertext =
        public_key.encrypt_time_lock(SignatureSchemes::ProofOfPossession, message, identity)?;
    Ok(ciphertext)
}

/// Verify and decrypt the ciphertext using signature shares
pub fn verify_and_decrypt_with_signatures_shares(
    public_key: &PublicKey<Bls12381G2Impl>,
    identity: &[u8],
    ciphertext: &TimeCryptCiphertext<Bls12381G2Impl>,
    shares: &[SignatureShare<Bls12381G2Impl>],
) -> SdkResult<Vec<u8>> {
    let signature = Signature::from_shares(shares)?;
    verify_and_decrypt(public_key, identity, ciphertext, &signature)
}

/// Verify and decrypt the ciphertext using the signature
pub fn verify_and_decrypt(
    public_key: &PublicKey<Bls12381G2Impl>,
    identity: &[u8],
    ciphertext: &TimeCryptCiphertext<Bls12381G2Impl>,
    signature: &Signature<Bls12381G2Impl>,
) -> SdkResult<Vec<u8>> {
    signature.verify(public_key, identity)?;
    let plaintext = Option::<Vec<u8>>::from(ciphertext.decrypt(signature))
        .ok_or_else(|| SdkError::Decryption("Decryption failure".to_string()))?;
    Ok(plaintext)
}
