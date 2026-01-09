use crate::{Error, Identifier, SigningShare, VerifyingKey};
use frost_core::Ciphersuite;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    num::NonZeroU16,
};

/// The frost keys used for signing generated during the DKG.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
pub struct KeyPackage {
    /// The identifier of the participant.
    pub identifier: Identifier,
    /// The secret share of the participant.
    pub secret_share: SigningShare,
    /// The public key of the group.
    pub verifying_key: VerifyingKey,
    /// The threshold of the group.
    pub threshold: NonZeroU16,
}

impl<C: Ciphersuite> From<frost_core::keys::KeyPackage<C>> for KeyPackage {
    fn from(s: frost_core::keys::KeyPackage<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::KeyPackage<C>> for KeyPackage {
    fn from(s: &frost_core::keys::KeyPackage<C>) -> Self {
        Self {
            identifier: s.identifier().into(),
            secret_share: s.signing_share().into(),
            verifying_key: s.verifying_key().into(),
            threshold: NonZeroU16::new(*s.min_signers()).expect("Threshold is zero"),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&KeyPackage> for frost_core::keys::KeyPackage<C> {
    type Error = Error;

    fn try_from(value: &KeyPackage) -> Result<Self, Self::Error> {
        let identifier = (&value.identifier).try_into()?;
        let secret_share: frost_core::keys::SigningShare<C> = (&value.secret_share).try_into()?;
        let verifying_share = frost_core::keys::VerifyingShare::<C>::from(secret_share);
        let group_public = (&value.verifying_key).try_into()?;
        let threshold = value.threshold.get();
        let key_package = frost_core::keys::KeyPackage::<C>::new(
            identifier,
            secret_share,
            verifying_share,
            group_public,
            threshold,
        );
        Ok(key_package)
    }
}

from_bytes_impl!(KeyPackage);

impl Display for KeyPackage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "identifier: {}, verifying_key: {}, threshold: {}",
            self.identifier, self.verifying_key, self.threshold
        )
    }
}
