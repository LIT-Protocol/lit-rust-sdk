use crate::{EncryptedPayload, SdkError, SdkResult};
use futures::{AsyncWrite, AsyncWriteExt, StreamExt};
use lit_node_core::NodeSet;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use uuid::Uuid;

/// The allowed http prefix
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UrlPrefix {
    /// http
    Http,
    #[default]
    /// https
    Https,
}

impl Display for UrlPrefix {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
        }
    }
}

impl FromStr for UrlPrefix {
    type Err = SdkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(SdkError::Parse(format!(
                "invalid url prefix '{}'. Expected 'http' or 'https'",
                s
            ))),
        }
    }
}

/// A single request for a single endpoint
#[derive(Clone, Debug)]
pub struct EndpointRequest<T>
where
    T: Serialize + DeserializeOwned + Sync,
{
    /// The node set information
    pub node_set: NodeSet,
    /// The node's identity key
    pub identity_key: NodeIdentityKey,
    /// The request to send to this node set
    pub body: T,
}

/// Node identity keys
pub type NodeIdentityKey = [u8; 32];

/// Admin endpoint requests
#[derive(Clone, Debug)]
pub struct AdminRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned,
{
    pub(crate) url_prefix: UrlPrefix,
    pub(crate) api_path: &'static str,
    pub(crate) custom_headers: HashMap<String, String>,
    pub(crate) public_address: String,
    pub(crate) inner: T,
    pub(crate) _builder: PhantomData<B>,
    pub(crate) _response: PhantomData<R>,
}

impl<B, T, R> AdminRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned,
{
    /// Create a new request builder
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> B {
        B::default()
    }

    /// The url prefix
    pub fn url_prefix(&self) -> &UrlPrefix {
        &self.url_prefix
    }

    /// The url suffix
    pub fn url_suffix(&self) -> &'static str {
        self.api_path
    }

    /// The public address to send the request
    pub fn public_address(&self) -> &str {
        &self.public_address
    }

    /// The custom headers to use
    pub fn custom_headers(&self) -> &HashMap<String, String> {
        &self.custom_headers
    }

    /// The request body
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Send the request to the specific [`NodeSet`]
    pub async fn send(&self) -> SdkResult<AdminResponse<R>> {
        let response_output = crate::request(
            self.url_prefix,
            &self.public_address,
            self.api_path,
            "",
            &self.custom_headers,
            &self.inner,
        )
        .await?;
        let out_headers = crate::extract_headers(&response_output)?;
        let output = response_output.text().await?;
        let response = serde_json::from_str(&output)?;
        Ok(AdminResponse {
            headers: out_headers,
            results: response,
        })
    }

    /// Write the output to a stream vs a string as returned by `send`
    pub async fn download<W>(&self, mut output: W) -> SdkResult<AdminResponse<()>>
    where
        W: AsyncWrite + Unpin,
    {
        let response = crate::request(
            self.url_prefix,
            &self.public_address,
            self.api_path,
            "",
            &self.custom_headers,
            &self.inner,
        )
        .await?;
        let out_headers = crate::extract_headers(&response)?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            output.write_all(&bytes).await?;
            output.flush().await?;
        }
        Ok(AdminResponse {
            headers: out_headers,
            results: (),
        })
    }
}

/// The response for an admin request
#[derive(Clone, Debug)]
pub struct AdminResponse<R>
where
    R: Serialize + DeserializeOwned,
{
    pub(crate) headers: HashMap<String, String>,
    pub(crate) results: R,
}

impl<R> AdminResponse<R>
where
    R: Serialize + DeserializeOwned,
{
    /// The results from the admin request
    pub fn results(&self) -> &R {
        &self.results
    }

    /// The response headers from the admin request
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
}

/// The general request for all SDK requests
#[derive(Clone, Debug)]
pub struct Request<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned,
{
    pub(crate) url_prefix: UrlPrefix,
    pub(crate) api_path: &'static str,
    pub(crate) node_set: Vec<NodeSet>,
    pub(crate) custom_headers: HashMap<String, String>,
    pub(crate) inner: T,
    pub(crate) request_id: Uuid,
    pub(crate) _builder: PhantomData<B>,
    pub(crate) _response: PhantomData<R>,
}

impl<B, T, R> Request<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned,
    R: Serialize + DeserializeOwned,
{
    /// Create a new request builder
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> B {
        B::default()
    }

    /// The url prefix
    pub fn url_prefix(&self) -> &UrlPrefix {
        &self.url_prefix
    }

    /// The url suffix
    pub fn url_suffix(&self) -> &'static str {
        self.api_path
    }

    /// The node set
    pub fn node_set(&self) -> &[NodeSet] {
        &self.node_set
    }

    /// The custom headers to use
    pub fn custom_headers(&self) -> &HashMap<String, String> {
        &self.custom_headers
    }

    /// The request body
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// The request id
    pub fn request_id(&self) -> &Uuid {
        &self.request_id
    }

    /// Send the request to the [`NodeSet`]
    pub async fn send(&self) -> SdkResult<Response<R>> {
        let mut headers = Vec::with_capacity(self.node_set.len());
        let mut responses = Vec::with_capacity(self.node_set.len());
        let request_id = self.request_id.to_string();
        let mut requests = Vec::with_capacity(self.node_set.len());

        for node in &self.node_set {
            requests.push(crate::request(
                self.url_prefix,
                &node.socket_address,
                self.api_path,
                &request_id,
                &self.custom_headers,
                &self.inner,
            ));
        }
        let results = futures::future::join_all(requests).await;
        for result in results {
            let response_output = result?;
            let out_headers = crate::extract_headers(&response_output)?;
            headers.push(out_headers);
            let output = response_output.text().await?;
            responses.push(serde_json::from_str(&output)?);
        }
        Ok(Response {
            headers,
            results: responses,
        })
    }
}

/// The general encrypted request for SDK requests
/// That sends the same request to each node
#[derive(Clone, Debug)]
pub struct EncryptedBroadcastRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned + Sync,
    R: Serialize + DeserializeOwned + Sync,
{
    pub(crate) url_prefix: UrlPrefix,
    pub(crate) api_path: &'static str,
    pub(crate) node_set: HashMap<NodeSet, NodeIdentityKey>,
    pub(crate) custom_headers: HashMap<String, String>,
    pub(crate) inner: T,
    pub(crate) request_id: Uuid,
    pub(crate) _builder: PhantomData<B>,
    pub(crate) _response: PhantomData<R>,
}

impl<B, T, R> EncryptedBroadcastRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned + Sync,
    R: Serialize + DeserializeOwned + Sync,
{
    /// Create a new request builder
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> B {
        B::default()
    }

    /// The url prefix
    pub fn url_prefix(&self) -> &UrlPrefix {
        &self.url_prefix
    }

    /// The url suffix
    pub fn url_suffix(&self) -> &'static str {
        self.api_path
    }

    /// The node set
    pub fn node_set(&self) -> &HashMap<NodeSet, NodeIdentityKey> {
        &self.node_set
    }

    /// The custom headers
    pub fn custom_headers(&self) -> &HashMap<String, String> {
        &self.custom_headers
    }

    /// The request body
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// The request id
    pub fn request_id(&self) -> &Uuid {
        &self.request_id
    }

    /// Send the request to the [`NodeSet`]
    pub async fn send(&self, my_secret_key: &[u8; 32]) -> SdkResult<Response<R>> {
        let mut headers = Vec::with_capacity(self.node_set.len());
        let mut responses = Vec::with_capacity(self.node_set.len());
        let body = serde_json::to_vec(&self.inner)?;
        let request_id = self.request_id.to_string();
        let mut requests = Vec::with_capacity(self.node_set.len());

        for (node, key) in &self.node_set {
            let payload = EncryptedPayload::<T>::encrypt(my_secret_key, key, &body);
            requests.push(crate::request(
                self.url_prefix,
                &node.socket_address,
                self.api_path,
                &request_id,
                &self.custom_headers,
                payload,
            ));
        }
        let results = futures::future::join_all(requests).await;
        for result in results {
            let response_output = result?;
            let out_headers = crate::extract_headers(&response_output)?;
            headers.push(out_headers);
            let output = response_output.text().await?;
            let des = serde_json::from_str::<EncryptedPayload<R>>(&output)?;
            let (r, _) = des.json_decrypt(my_secret_key)?;
            responses.push(r);
        }

        Ok(Response {
            headers,
            results: responses,
        })
    }
}

/// The general encrypted request for SDK requests
/// That sends a different request to each node
#[derive(Clone, Debug)]
pub struct EncryptedMulticastRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned + Sync,
    R: Serialize + DeserializeOwned + Sync,
{
    pub(crate) url_prefix: UrlPrefix,
    pub(crate) api_path: &'static str,
    pub(crate) node_set: Vec<EndpointRequest<T>>,
    pub(crate) custom_headers: HashMap<String, String>,
    pub(crate) request_id: Uuid,
    pub(crate) _builder: PhantomData<B>,
    pub(crate) _response: PhantomData<R>,
}

impl<B, T, R> EncryptedMulticastRequest<B, T, R>
where
    B: Sized + Default,
    T: Serialize + DeserializeOwned + Sync,
    R: Serialize + DeserializeOwned + Sync,
{
    /// Create a new request builder
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> B {
        B::default()
    }

    /// The url prefix
    pub fn url_prefix(&self) -> &UrlPrefix {
        &self.url_prefix
    }

    /// The url suffix
    pub fn url_suffix(&self) -> &'static str {
        self.api_path
    }

    /// The node set and requests
    pub fn node_set(&self) -> &[EndpointRequest<T>] {
        &self.node_set
    }

    /// The custom headers
    pub fn custom_headers(&self) -> &HashMap<String, String> {
        &self.custom_headers
    }

    /// The request id
    pub fn request_id(&self) -> &Uuid {
        &self.request_id
    }

    /// Send a request to each node in [`NodeSet`]
    pub async fn send(&self, my_secret_key: &[u8; 32]) -> SdkResult<Response<R>> {
        let mut headers = Vec::with_capacity(self.node_set.len());
        let mut responses = Vec::with_capacity(self.node_set.len());
        let request_id = self.request_id.to_string();
        let mut requests = Vec::with_capacity(self.node_set.len());

        for endpoint in &self.node_set {
            let body = serde_json::to_vec(&endpoint.body)?;
            let payload =
                EncryptedPayload::<T>::encrypt(my_secret_key, &endpoint.identity_key, &body);
            requests.push(crate::request(
                self.url_prefix,
                &endpoint.node_set.socket_address,
                self.api_path,
                &request_id,
                &self.custom_headers,
                payload,
            ));
        }
        let results = futures::future::join_all(requests).await;
        for result in results {
            let response_output = result?;
            let out_headers = crate::extract_headers(&response_output)?;
            headers.push(out_headers);
            let output = response_output.text().await?;
            let des = serde_json::from_str::<EncryptedPayload<R>>(&output)?;
            let (r, _) = des.json_decrypt(my_secret_key)?;
            responses.push(r);
        }

        Ok(Response {
            headers,
            results: responses,
        })
    }
}

/// The general response for all SDK responses
#[derive(Clone, Debug)]
pub struct Response<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(crate) results: Vec<T>,
    pub(crate) headers: Vec<HashMap<String, String>>,
}

impl<T> Response<T>
where
    T: Serialize + DeserializeOwned,
{
    /// The results from the SDK request
    ///
    /// The ordering is the same as the node_set
    pub fn results(&self) -> &Vec<T> {
        &self.results
    }

    /// The Response headers from the SDK request
    ///
    /// The ordering is the same as the node_set
    pub fn headers(&self) -> &Vec<HashMap<String, String>> {
        &self.headers
    }
}
