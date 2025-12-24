use crate::error::LitSdkError;
use serde::{Deserialize, Serialize};

// Re-export lit-sdk's EncryptedPayload for raw bytes
pub type EncryptedPayload = lit_sdk::EncryptedPayload<Vec<u8>>;

/// Try to decrypt an encrypted payload with any of the given secret keys.
/// Returns the decrypted data if any key works.
pub fn wallet_decrypt_with_any_key(
    secret_keys: &[[u8; 32]],
    data: &EncryptedPayload,
) -> Result<Vec<u8>, LitSdkError> {
    for secret_key in secret_keys {
        if let Ok((decrypted, _)) = data.decrypt(secret_key) {
            return Ok(decrypted);
        }
    }
    Err(LitSdkError::Crypto(
        "E2EE decryption failed with all available keys".into(),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericEncryptedPayload {
    pub success: bool,
    #[serde(default)]
    pub values: Vec<EncryptedPayload>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

fn always_32_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[..32]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(bytes);
    }
    out
}

pub fn wallet_encrypt(
    my_secret_key: &[u8; 32],
    their_public_key_bytes: &[u8],
    message: &[u8],
) -> Result<EncryptedPayload, LitSdkError> {
    let their_pk = always_32_bytes(their_public_key_bytes);
    Ok(EncryptedPayload::encrypt(my_secret_key, &their_pk, message))
}

pub fn wallet_decrypt(
    my_secret_key: &[u8; 32],
    data: &EncryptedPayload,
) -> Result<Vec<u8>, LitSdkError> {
    let (decrypted, _their_pk) = data
        .decrypt(my_secret_key)
        .map_err(|e| LitSdkError::Crypto(e.to_string()))?;
    Ok(decrypted)
}
