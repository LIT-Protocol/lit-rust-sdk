use crate::AuthMaterialType;
use crate::constants::{
    AUTH_SIG_BLS_NETWORK_SIG_ALGO, AUTH_SIG_DERIVED_VIA_BLS_NETWORK_SIG,
    AUTH_SIG_DERIVED_VIA_CONTRACT_SIG, AUTH_SIG_DERIVED_VIA_CONTRACT_SIG_SHA256,
    AUTH_SIG_DERIVED_VIA_SESSION_SIG, AUTH_SIG_SESSION_SIG_ALGO, Chain,
};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// This struct is used both to represent various authentication material,
/// e.g. wallet sigs, session sigs or cosmos auth sigs etc.
#[derive(Serialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "camelCase")]
pub struct JsonAuthSig {
    pub sig: String,
    pub derived_via: String,
    pub signed_message: String,

    // TODO: Make this private once extract_user_address has stabilized
    pub address: String,
    pub algo: Option<String>,

    #[serde(skip)]
    pub auth_material_type: AuthMaterialType,

    /// The chain that the auth sig has been validated against.
    ///
    /// This is None if the auth sig has not been validated yet.
    #[serde(skip)]
    pub chain: Option<Chain>,
}

#[cfg(not(test))]
impl fmt::Debug for JsonAuthSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonAuthSig")
            .field("sig", &"****filtered****")
            .field("derived_via", &self.derived_via)
            .field("signed_message", &self.signed_message)
            .field("address", &self.address)
            .field("algo", &self.algo)
            .field("auth_material_type", &self.auth_material_type)
            .field("chain", &self.chain)
            .finish()
    }
}

impl fmt::Display for JsonAuthSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JsonAuthSig {{ sig: ****filtered****, derived_via: {}, signed_message: {}, address: {}, algo: {:?}, auth_material_type: {:?}, chain: {:?} }}",
            self.derived_via,
            self.signed_message,
            self.address,
            self.algo,
            self.auth_material_type,
            self.chain
        )
    }
}

impl JsonAuthSig {
    pub fn new(
        sig: String,
        derived_via: String,
        signed_message: String,
        address: String,
        algo: Option<String>,
    ) -> Self {
        JsonAuthSig {
            sig,
            derived_via,
            signed_message,
            address,
            algo,
            auth_material_type: AuthMaterialType::default(),
            chain: None,
        }
    }

    pub fn new_with_type(
        sig: String,
        derived_via: String,
        signed_message: String,
        address: String,
        algo: Option<String>,
        auth_material_type: AuthMaterialType,
        chain: Option<Chain>,
    ) -> Self {
        JsonAuthSig {
            sig,
            derived_via,
            signed_message,
            address,
            algo,
            auth_material_type,
            chain,
        }
    }

    /// Always defaults to interpreting as a wallet sig. This is only because
    /// we don't want to break clients too much.
    ///
    /// TODO: After a stabilization period, we should make our pattern matching
    /// stricter and perhaps turn this function to returning a core::Result.
    #[allow(clippy::collapsible_if)]
    pub fn determine_auth_material_type(
        derived_via: &str,
        algo: &Option<String>,
    ) -> AuthMaterialType {
        if let Some(algo) = algo {
            if derived_via == AUTH_SIG_DERIVED_VIA_SESSION_SIG && algo == AUTH_SIG_SESSION_SIG_ALGO
            {
                return AuthMaterialType::SessionSig;
            }
        }

        if derived_via == AUTH_SIG_DERIVED_VIA_CONTRACT_SIG
            || derived_via == AUTH_SIG_DERIVED_VIA_CONTRACT_SIG_SHA256
        {
            return AuthMaterialType::ContractSig;
        }

        if let Some(algo) = algo {
            if derived_via == AUTH_SIG_DERIVED_VIA_BLS_NETWORK_SIG
                && algo == AUTH_SIG_BLS_NETWORK_SIG_ALGO
            {
                return AuthMaterialType::BLSNetworkSig;
            }
        }

        AuthMaterialType::WalletSig
    }
}

// Custom deserialization logic for JsonAuthSig

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum JsonAuthSigField {
    Sig,
    DerivedVia,
    SignedMessage,
    Address,
    Algo,
}

impl<'de> Deserialize<'de> for JsonAuthSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JsonAuthSigVisitor)
    }
}

struct JsonAuthSigVisitor;

impl<'de> Visitor<'de> for JsonAuthSigVisitor {
    type Value = JsonAuthSig;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a map with keys sig, derivedVia, signedMessage, address, and optionally algo"
        )
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut sig = None;
        let mut derived_via = None;
        let mut signed_message = None;
        let mut address = None;
        let mut algo = None;

        while let Some(key) = map.next_key()? {
            match key {
                JsonAuthSigField::Sig => {
                    if sig.is_some() {
                        return Err(serde::de::Error::duplicate_field("sig"));
                    }
                    sig = Some(map.next_value()?);
                }
                JsonAuthSigField::DerivedVia => {
                    if derived_via.is_some() {
                        return Err(serde::de::Error::duplicate_field("derived_via"));
                    }
                    derived_via = Some(map.next_value()?);
                }
                JsonAuthSigField::SignedMessage => {
                    if signed_message.is_some() {
                        return Err(serde::de::Error::duplicate_field("signed_message"));
                    }
                    signed_message = Some(map.next_value()?);
                }
                JsonAuthSigField::Address => {
                    if address.is_some() {
                        return Err(serde::de::Error::duplicate_field("address"));
                    }
                    address = Some(map.next_value()?);
                }
                JsonAuthSigField::Algo => {
                    if algo.is_some() {
                        return Err(serde::de::Error::duplicate_field("algo"));
                    }
                    algo = map.next_value()?;
                }
            }
        }

        let sig: String = sig.ok_or_else(|| serde::de::Error::missing_field("sig"))?;
        let derived_via: String =
            derived_via.ok_or_else(|| serde::de::Error::missing_field("derived_via"))?;
        let signed_message: String =
            signed_message.ok_or_else(|| serde::de::Error::missing_field("signed_message"))?;
        let address: String = address.ok_or_else(|| serde::de::Error::missing_field("address"))?;

        // Determine the auth material type
        let auth_material_type = JsonAuthSig::determine_auth_material_type(&derived_via, &algo);

        Ok(JsonAuthSig::new_with_type(
            sig,
            derived_via,
            signed_message,
            address,
            algo,
            auth_material_type,
            None,
        ))
    }
}

/// The auth sig used when calling admin endpoints
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuthSig {
    /// The inner auth sig
    pub auth_sig: JsonAuthSig,
}
