use crate::constants::{
    LIT_RESOURCE_PREFIX_ACC, LIT_RESOURCE_PREFIX_LA, LIT_RESOURCE_PREFIX_PD,
    LIT_RESOURCE_PREFIX_PKP,
};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum LitResourcePrefix {
    ACC,
    PKP,
    LA,
    PD,
}

impl fmt::Display for LitResourcePrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ACC => write!(f, "{}", LIT_RESOURCE_PREFIX_ACC),
            Self::PKP => write!(f, "{}", LIT_RESOURCE_PREFIX_PKP),
            Self::LA => write!(f, "{}", LIT_RESOURCE_PREFIX_LA),
            Self::PD => write!(f, "{}", LIT_RESOURCE_PREFIX_PD),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseLitResourcePrefixError;

impl FromStr for LitResourcePrefix {
    type Err = ParseLitResourcePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            LIT_RESOURCE_PREFIX_ACC => Ok(Self::ACC),
            LIT_RESOURCE_PREFIX_PKP => Ok(Self::PKP),
            LIT_RESOURCE_PREFIX_LA => Ok(Self::LA),
            LIT_RESOURCE_PREFIX_PD => Ok(Self::PD),
            _ => Err(ParseLitResourcePrefixError),
        }
    }
}
