use crate::{SdkError, SdkResult};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

const ENCRYPTED_PAYLOAD_CURRENT_VERSION: u8 = 1;

/// An encrypted payload that can be sent between wallets.
///
/// The payload is encrypted using the sender's private key and the recipient's
/// public key. The recipient can decrypt the payload using their private key
/// and the sender's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "version",
    content = "payload",
    bound = "I: Serialize + DeserializeOwned + Sync"
)]
pub enum EncryptedPayload<I: Serialize + DeserializeOwned + Sync> {
    /// The current version of the payload
    #[serde(rename = "1")]
    V1(Box<EncryptedPayloadV1<I>>),
}

impl<I: Serialize + DeserializeOwned + Sync> From<EncryptedPayloadV1<I>> for EncryptedPayload<I> {
    fn from(payload: EncryptedPayloadV1<I>) -> Self {
        Self::V1(Box::new(payload))
    }
}

impl<I: Serialize + DeserializeOwned + Sync> EncryptedPayload<I> {
    /// Serialize a payload to JSON then encrypt it
    pub fn json_encrypt(
        my_secret_key: &[u8; 32],
        their_public_key: &[u8; 32],
        msg: &I,
    ) -> SdkResult<Self> {
        let msg_json = serde_json::to_vec(msg)?;
        Ok(Self::encrypt(my_secret_key, their_public_key, &msg_json))
    }

    /// Upon successful decryption of the payload, deserialize it from JSON
    /// and also return the incoming public key that was used for encryption
    pub fn json_decrypt(&self, my_keys: &[u8; 32]) -> SdkResult<(I, [u8; 32])> {
        let (decrypted, their_public_key) = self.decrypt(my_keys)?;
        let msg = serde_json::from_slice(&decrypted)?;
        Ok((msg, their_public_key))
    }

    /// Encrypt a message for a recipient.
    pub fn encrypt(my_secret_key: &[u8; 32], their_public_key: &[u8; 32], msg: &[u8]) -> Self {
        let random = rand::rngs::OsRng.r#gen::<[u8; 16]>();
        let created_at = Utc::now();
        let timestamp = created_at.timestamp() as u64;
        let mut my_public_key = [0u8; 32];
        sodalite::scalarmult_base(&mut my_public_key, my_secret_key);
        let aad: Vec<u8> = std::iter::once(ENCRYPTED_PAYLOAD_CURRENT_VERSION)
            .chain(random.iter().copied())
            .chain(timestamp.to_be_bytes().iter().copied())
            .chain(their_public_key.iter().copied())
            .chain(my_public_key.iter().copied())
            .collect();

        // Tweetnacl doesn't support AAD, so we have to manually add
        // it by hashing the aad and taking the first 24 bytes
        // as the nonce.
        let mut hash = [0u8; 64];
        sodalite::hash(&mut hash, &aad);
        let nonce: [u8; 24] = (&hash[..24]).try_into().expect("Failed to convert nonce");

        let mut plaintext = vec![0u8; 32];
        plaintext.extend_from_slice(msg);
        let mut ciphertext_and_tag = vec![0u8; plaintext.len()];
        {
            sodalite::box_(
                &mut ciphertext_and_tag,
                &plaintext,
                &nonce,
                their_public_key,
                my_secret_key,
            )
            .expect("Failed to encrypt message");
        }

        EncryptedPayloadV1 {
            verification_key: my_public_key,
            random,
            created_at,
            ciphertext_and_tag,
            _inner_representation: PhantomData,
        }
        .into()
    }

    /// Decrypt a message from a sender.
    pub fn decrypt(&self, my_secret_key: &[u8; 32]) -> SdkResult<(Vec<u8>, [u8; 32])> {
        let mut my_public_key = [0u8; 32];
        sodalite::scalarmult_base(&mut my_public_key, my_secret_key);
        match self {
            Self::V1(v1) => {
                let timestamp = v1.created_at.timestamp() as u64;
                let aad = std::iter::once(ENCRYPTED_PAYLOAD_CURRENT_VERSION)
                    .chain(v1.random.iter().copied())
                    .chain(timestamp.to_be_bytes().iter().copied())
                    .chain(my_public_key.iter().copied())
                    .chain(v1.verification_key.iter().copied())
                    .collect::<Vec<_>>();

                // Tweetnacl doesn't support AAD, so we have to manually add
                // it by hashing the aad and taking the first 24 bytes
                // as the nonce.
                let mut hash = [0u8; 64];
                sodalite::hash(&mut hash, &aad);
                let nonce: [u8; 24] = (&hash[..24]).try_into().expect("Failed to convert nonce");
                let mut plaintext = vec![0u8; v1.ciphertext_and_tag.len()];
                {
                    sodalite::box_open(
                        &mut plaintext,
                        &v1.ciphertext_and_tag,
                        &nonce,
                        &v1.verification_key,
                        my_secret_key,
                    )
                    .map_err(|_| {
                        SdkError::Decryption("encrypted payload decryption failed".to_string())
                    })?;
                }
                Ok((plaintext[32..].to_vec(), v1.verification_key))
            }
        }
    }
}

/// Encrypted payload structure for version 1
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedPayloadV1<I: Serialize + DeserializeOwned + Sync> {
    /// The public key of the sender.
    #[serde(with = "hex")]
    verification_key: [u8; 32],
    /// The random nonce when encrypting the ciphertext.
    #[serde(with = "hex")]
    random: [u8; 16],
    /// The timestamp when the payload was created.
    #[serde(with = "chrono_rfc3339")]
    created_at: DateTime<Utc>,
    /// The encrypted payload.
    #[serde(with = "hex")]
    ciphertext_and_tag: Vec<u8>,
    /// The inner representation of the payload
    ///
    /// Useful to present serializing and deserializing from one object to another
    /// by mistake of the wrong type and for readability.
    #[serde(skip)]
    _inner_representation: PhantomData<I>,
}

mod chrono_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S>(date: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        date.to_rfc3339().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&s)
            .map_err(serde::de::Error::custom)
            .map(DateTime::from)
    }
}
