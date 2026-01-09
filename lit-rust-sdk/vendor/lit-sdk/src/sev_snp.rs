use crate::{SdkError, SdkResult};
use sev::{
    certs::snp::{Certificate, Chain, Verifiable, builtin::milan, ca},
    firmware::{guest::AttestationReport, host::TcbVersion},
};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// Handler for Sev SNP attestation reports for LIT
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SevSnp;

impl SevSnp {
    /// The KDS CERT url
    pub const KDS_CERT_SITE: &'static str = "https://kdsintf.amd.com";
    /// The sub url
    pub const KDS_VCEK: &'static str = "/vcek/v1";
    /// The product name
    pub const PRODUCT_NAME: &'static str = "Milan";

    /// Get the vcek url
    pub fn vcek_url(attestation_report: &AttestationReport) -> String {
        let AttestationReport {
            chip_id,
            reported_tcb:
                TcbVersion {
                    bootloader,
                    tee,
                    snp,
                    microcode,
                    ..
                },
            ..
        } = attestation_report;

        format!(
            "{}{}{}/{}?blSPL={bootloader:0>2}&teeSPL={tee:0>2}&snpSPL={snp:0>2}&ucodeSPL={microcode:0>2}",
            Self::KDS_CERT_SITE,
            Self::KDS_VCEK,
            Self::PRODUCT_NAME,
            hex::encode(chip_id)
        )
    }

    /// Verify the attestation report and provided inner data
    pub fn verify(
        attestation_report: &AttestationReport,
        attestation_data: &BTreeMap<String, Vec<u8>>,
        signatures: &[Vec<u8>],
        challenge: &[u8],
        vcek_certificate: &Certificate,
    ) -> SdkResult<()> {
        verify_certificate(vcek_certificate, attestation_report)?;
        verify_challenge(challenge, attestation_data, signatures, attestation_report)
    }
}

fn verify_certificate(vek: &Certificate, report: &AttestationReport) -> SdkResult<()> {
    let ark = milan::ark().expect("to get the ark");
    let ask = milan::ask().expect("to get the ask");

    let ca = ca::Chain { ark, ask };
    let chain = Chain {
        ca,
        vek: vek.clone(),
    };
    Verifiable::verify((&chain, report))?;
    Ok(())
}

fn verify_challenge(
    challenge: &[u8],
    data: &BTreeMap<String, Vec<u8>>,
    signatures: &[Vec<u8>],
    attestation_report: &AttestationReport,
) -> SdkResult<()> {
    let mut hasher = Sha512::default();
    hasher.update("noonce");
    hasher.update(challenge);

    hasher.update("data");
    for (key, value) in data {
        hasher.update(key);
        hasher.update(value);
    }
    if !signatures.is_empty() {
        hasher.update("signatures");
        for signature in signatures {
            hasher.update(signature);
        }
    }

    let hash: [u8; 64] = hasher.finalize().into();

    if attestation_report.report_data != hash {
        return Err(SdkError::Attestation);
    }
    Ok(())
}
