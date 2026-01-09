//!
//! The Rust Lit-Node SDK
//!

#[macro_use]
mod macros;
pub mod admin;
#[cfg(feature = "cait-sith")]
pub mod cait_sith;
mod common;
pub mod encryption;
mod error;
mod execute_function;
mod handshake;
mod payload;
mod pkp_claim;
mod pkp_sign;
mod session_key;
mod sev_snp;
pub mod signature;

pub use common::*;
pub use encryption::{EncryptionSignRequest, EncryptionSignRequestBuilder, EncryptionSignResponse};
pub use error::*;
pub use execute_function::*;
pub use handshake::*;
pub use payload::*;
pub use pkp_claim::*;
pub use pkp_sign::*;
pub use session_key::*;
pub use sev_snp::*;

pub use lit_node_core;
pub use sev;
pub use uuid;

use serde::Serialize;
use std::{collections::HashMap, sync::OnceLock, time::Duration};

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder
            .pool_idle_timeout(Some(Duration::from_secs(10)))
            .tls_sni(false);
        builder
            .build()
            .expect("Failed to build HTTP client")
    })
}

/// Compute the ipfs hash of a string
pub fn compute_ipfs_hash(code: &str) -> String {
    ipfs_hasher::IpfsHasher::default().compute(code.as_bytes())
}

async fn request<B>(
    url_prefix: UrlPrefix,
    socket_address: &str,
    api_path: &str,
    request_id: &str,
    custom_headers: &HashMap<String, String>,
    body: B,
) -> SdkResult<reqwest::Response>
where
    B: Serialize,
{
    let client = get_http_client();
    let mut request_builder = client
        .post(format!("{}://{}/{}", url_prefix, socket_address, api_path))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if !request_id.is_empty() {
        request_builder = request_builder.header("X-Request-Id", request_id);
    }
    for (custom_header, value) in custom_headers {
        request_builder = request_builder.header(custom_header, value);
    }
    let response_output = request_builder
        .body(serde_json::to_string(&body)?)
        .send()
        .await?;
    Ok(response_output)
}

fn extract_headers(response_output: &reqwest::Response) -> SdkResult<HashMap<String, String>> {
    let response_headers = response_output.headers();
    let mut out_headers = HashMap::with_capacity(response_headers.len());
    for (k, v) in response_headers {
        out_headers.insert(k.to_string(), v.to_str()?.to_string());
    }
    Ok(out_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_prefix_parse() {
        assert_eq!(UrlPrefix::Http, "http".parse::<UrlPrefix>().unwrap());
        assert_eq!(UrlPrefix::Http, "HTTP".parse::<UrlPrefix>().unwrap());
        assert_eq!(UrlPrefix::Https, "https".parse::<UrlPrefix>().unwrap());
        assert_eq!(UrlPrefix::Https, "HTTPS".parse::<UrlPrefix>().unwrap());
        assert!("ftp".parse::<UrlPrefix>().is_err());
    }

    #[test]
    fn url_prefix_to_string() {
        assert_eq!(UrlPrefix::Http.to_string(), "http");
        assert_eq!(UrlPrefix::Https.to_string(), "https");
    }

    #[test]
    fn url_prefix_default() {
        assert_eq!(UrlPrefix::Https, UrlPrefix::default());
    }
}
