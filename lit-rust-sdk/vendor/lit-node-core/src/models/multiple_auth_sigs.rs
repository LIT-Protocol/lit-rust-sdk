use crate::JsonAuthSig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipleAuthSigs {
    pub ethereum: Option<JsonAuthSig>,
    pub solana: Option<JsonAuthSig>,
    pub cosmos: Option<JsonAuthSig>,
    pub kyve: Option<JsonAuthSig>,
    pub cheqd: Option<JsonAuthSig>,
    pub juno: Option<JsonAuthSig>,
}

impl MultipleAuthSigs {
    pub fn populate_by_chain(chain: &Option<String>, auth_sig: &JsonAuthSig) -> MultipleAuthSigs {
        let mut mult_auth_sigs = MultipleAuthSigs::default();

        match chain {
            None => {
                mult_auth_sigs.ethereum = Some(auth_sig.to_owned());
            }
            Some(chain) => match chain.as_str() {
                "solana" | "solanaDevnet" | "solanaTestnet" => {
                    mult_auth_sigs.solana = Some(auth_sig.to_owned());
                }
                "cosmos" => {
                    mult_auth_sigs.cosmos = Some(auth_sig.to_owned());
                }
                "kyve" => {
                    mult_auth_sigs.kyve = Some(auth_sig.to_owned());
                }
                "cheqd" | "cheqdMainnet" | "cheqdTestnet" => {
                    mult_auth_sigs.cheqd = Some(auth_sig.to_owned());
                }
                "juno" => {
                    mult_auth_sigs.juno = Some(auth_sig.to_owned());
                }
                _ => {
                    mult_auth_sigs.ethereum = Some(auth_sig.to_owned());
                }
            },
        }

        mult_auth_sigs
    }
}
