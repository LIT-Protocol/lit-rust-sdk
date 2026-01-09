use crate::Error;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(unused)]
pub enum AttestationType {
    AmdSevSnp,
    AdminSigned,
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AttestationType::AmdSevSnp => write!(f, "AMD_SEV_SNP"),
            AttestationType::AdminSigned => write!(f, "ADMIN_SIGNED"),
        }
    }
}

impl FromStr for AttestationType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AMD_SEV_SNP" => Ok(AttestationType::AmdSevSnp),
            "ADMIN_SIGNED" => Ok(AttestationType::AdminSigned),
            _ => Err(Error::InvalidType(format!(
                "{} is not a valid AttestationType",
                s
            ))),
        }
    }
}
