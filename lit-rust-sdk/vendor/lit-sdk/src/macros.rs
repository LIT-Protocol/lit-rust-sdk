macro_rules! url_prefix {
    () => {
        /// Set the url prefix for the handshake request
        pub fn url_prefix(self, url_prefix: UrlPrefix) -> Self {
            Self {
                url_prefix: Some(url_prefix),
                ..self
            }
        }
    };
}

macro_rules! custom_headers {
    () => {
        /// Set the custom headers to be used
        pub fn custom_headers(self, custom_headers: HashMap<String, String>) -> Self {
            Self {
                custom_headers: Some(custom_headers),
                ..self
            }
        }

        /// Set the custom headers to be used from an iterator
        pub fn custom_headers_from_iter<'a, I>(self, custom_headers: I) -> Self
        where
            I: Iterator<Item = (&'a String, &'a String)>,
        {
            Self {
                custom_headers: Some(
                    custom_headers
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                ),
                ..self
            }
        }

        /// Add a custom header that will be used for the request
        pub fn add_custom_header(mut self, header_name: &str, header_value: &str) -> Self {
            if let Some(mut headers) = self.custom_headers.take() {
                headers.insert(header_name.to_owned(), header_value.to_owned());
                Self {
                    custom_headers: Some(headers),
                    ..self
                }
            } else {
                let mut headers = HashMap::new();
                headers.insert(header_name.to_owned(), header_value.to_owned());
                Self {
                    custom_headers: Some(headers),
                    ..self
                }
            }
        }
    };
}

macro_rules! request_id {
    () => {
        /// Set the request_id
        pub fn request_id(self, request_id: Uuid) -> Self {
            Self {
                request_id: Some(request_id),
                ..self
            }
        }
    };
}

macro_rules! node_set {
    ($node_set:ty) => {
        /// Set the node set that will receive the handshake request
        pub fn node_set(self, node_set: $node_set) -> Self {
            Self {
                node_set: Some(node_set),
                ..self
            }
        }
    };
}

macro_rules! request {
    ($request:ty) => {
        /// Set the request body for the request
        pub fn request(self, request: $request) -> Self {
            Self {
                request: Some(request),
                ..self
            }
        }
    };
}

macro_rules! base_builder {
    (
        $name:ident,
        $request:ty,
        $response:ty,
        $api_path:expr,
        $node_set:ty,
        $inner_request:ident
    ) => {
        /// The request builder
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            url_prefix: Option<UrlPrefix>,
            custom_headers: Option<HashMap<String, String>>,
            node_set: Option<$node_set>,
            request: Option<$request>,
            request_id: Option<Uuid>,
        }

        impl $name {
            url_prefix!();
            custom_headers!();
            request_id!();
            node_set!($node_set);
            request!($request);

            /// Finalize the handshake request
            pub fn build(self) -> SdkResult<$inner_request<$name, $request, $response>> {
                if let Some(node_set) = &self.node_set {
                    if node_set.is_empty() {
                        return Err(SdkError::Build("No node_set is specified".to_string()));
                    }
                }
                self.request_checks()?;

                let request_id = self.request_id.unwrap_or_else(Uuid::new_v4);
                Ok($inner_request {
                    url_prefix: self.url_prefix.unwrap_or_default(),
                    api_path: $api_path,
                    node_set: self
                        .node_set
                        .ok_or(SdkError::Build("No node_set is specified".to_string()))?,
                    request_id,
                    custom_headers: self.custom_headers.unwrap_or_default(),
                    inner: self
                        .request
                        .ok_or(SdkError::Build("No request is specified".to_string()))?,
                    _builder: PhantomData,
                    _response: PhantomData,
                })
            }
        }
    };
}

/// Create the template for the request builder struct
macro_rules! basic_builder {
    (
        $name:ident,
        $request:ty,
        $response:ty,
        $api_path:expr
    ) => {
        base_builder!($name, $request, $response, $api_path, Vec<NodeSet>, Request);
        impl $name {
            /// Set the node set that will receive the handshake request from an iterator
            pub fn node_set_from_iter<'a, I>(self, node_set: I) -> Self
            where
                I: Iterator<Item = &'a NodeSet>,
            {
                Self {
                    node_set: Some(node_set.map(|v| v.to_owned()).collect()),
                    ..self
                }
            }

            /// Add a node set that will receive the handshake request
            pub fn add_node_set(mut self, node_set: NodeSet) -> Self {
                if let Some(mut set) = self.node_set.take() {
                    set.push(node_set);
                    Self {
                        node_set: Some(set),
                        ..self
                    }
                } else {
                    Self {
                        node_set: Some(vec![node_set]),
                        ..self
                    }
                }
            }
        }
    };
}

macro_rules! encrypted_builder {
    (
        $name:ident,
        $request:ty,
        $response:ty,
        $api_path:expr
    ) => {
        base_builder!($name, $request, $response, $api_path, HashMap<NodeSet, NodeIdentityKey>, EncryptedBroadcastRequest);

        impl $name {
            /// Set the node set that will receive the handshake request from an iterator
            pub fn node_set_from_iter<'a, I>(self, node_set: I) -> Self
            where
                I: Iterator<Item = (&'a NodeSet, &'a NodeIdentityKey)>,
            {
                Self {
                    node_set: Some(
                        node_set
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect(),
                    ),
                    ..self
                }
            }

            /// Add a node set that will receive the handshake request
            pub fn add_node_set(
                mut self,
                (node_set, node_identity_key): (NodeSet, NodeIdentityKey),
            ) -> Self {
                if let Some(mut set) = self.node_set.take() {
                    set.insert(node_set, node_identity_key);
                    Self {
                        node_set: Some(set),
                        ..self
                    }
                } else {
                    let mut set = HashMap::new();
                    set.insert(node_set, node_identity_key);
                    Self {
                        node_set: Some(set),
                        ..self
                    }
                }
            }
        }
    };
}

macro_rules! encrypted_multicast_builder {
    (
        $name:ident,
        $request:ty,
        $response:ty,
        $api_path:expr
    ) => {
        /// The request builder
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            url_prefix: Option<UrlPrefix>,
            custom_headers: Option<HashMap<String, String>>,
            node_set: Option<Vec<EndpointRequest<$request>>>,
            request_id: Option<Uuid>,
        }

        impl $name {
            url_prefix!();
            custom_headers!();
            request_id!();
            node_set!(Vec<EndpointRequest<$request>>);

            /// Finalize the handshake request
            pub fn build(self) -> SdkResult<EncryptedMulticastRequest<$name, $request, $response>> {
                if let Some(node_set) = &self.node_set {
                    if node_set.is_empty() {
                        return Err(SdkError::Build("No node_set is specified".to_string()));
                    }
                }
                self.request_checks()?;

                let request_id = self.request_id.unwrap_or_else(Uuid::new_v4);
                Ok(EncryptedMulticastRequest {
                    url_prefix: self.url_prefix.unwrap_or_default(),
                    api_path: $api_path,
                    node_set: self
                        .node_set
                        .ok_or(SdkError::Build("No node_set is specified".to_string()))?,
                    request_id,
                    custom_headers: self.custom_headers.unwrap_or_default(),
                    _builder: PhantomData,
                    _response: PhantomData,
                })
            }
        }
    };
}

/// Create a setter method for the builder struct
macro_rules! builder_setter {
    ($fn_name:ident, $param_name:ident, Option<$param_type:ty>, $request_type:ty, $field_name:ident) => {
        #[doc = concat!("Set the ", stringify!($fn_name), " parameter for the request")]
        pub fn $fn_name(mut self, $param_name: $param_type) -> Self {
            let request = if let Some(mut request) = self.request.take() {
                request.$field_name = Some($param_name);
                request
            } else {
                let mut request = <$request_type>::default();
                request.$field_name = Some($param_name);
                request
            };
            self.request(request)
        }
    };
    ($fn_name:ident, $param_name:ident, Vec<$param_type:ty>, $request_type:ty, $field_name:ident) => {
        #[doc = concat!("Set the ", stringify!($fn_name), " parameter for the request")]
        pub fn $fn_name(mut self, $param_name: $param_type) -> Self {
            let request = if let Some(mut request) = self.request.take() {
                request.$field_name.push($param_name);
                request
            } else {
                let mut request = <$request_type>::default();
                request.$field_name.push($param_name);
                request
            };
            self.request(request)
        }
    };
    ($fn_name:ident, $param_name:ident, $param_type:ty, $request_type:ty, $field_name:ident) => {
        #[doc = concat!("Set the ", stringify!($fn_name), " parameter for the request")]
        pub fn $fn_name(mut self, $param_name: $param_type) -> Self {
            let request = if let Some(mut request) = self.request.take() {
                request.$field_name = $param_name;
                request
            } else {
                let mut request = <$request_type>::default();
                request.$field_name = $param_name;
                request
            };
            self.request(request)
        }
    };
}

/// Create the template for the admin request builder struct
macro_rules! admin_builder {
    (
        $name:ident,
        $request:ident,
        $response:ty,
        $api_path:expr
    ) => {
        /// The request builder
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            url_prefix: Option<UrlPrefix>,
            custom_headers: Option<HashMap<String, String>>,
            public_address: Option<String>,
            request: Option<$request>,
        }

        impl $name {
            url_prefix!();
            custom_headers!();
            request!($request);

            /// Set the public address to send the request
            pub fn public_address(self, public_address: String) -> Self {
                Self {
                    public_address: Some(public_address),
                    ..self
                }
            }

            /// Finalize the handshake request
            pub fn build(self) -> SdkResult<AdminRequest<$name, $request, $response>> {
                self.request_checks()?;

                Ok(AdminRequest {
                    url_prefix: self.url_prefix.unwrap_or_default(),
                    api_path: $api_path,
                    public_address: self.public_address.ok_or(SdkError::Build(
                        "No public address is specified".to_string(),
                    ))?,
                    custom_headers: self.custom_headers.unwrap_or_default(),
                    inner: self
                        .request
                        .ok_or(SdkError::Build("No request is specified".to_string()))?,
                    _builder: PhantomData,
                    _response: PhantomData,
                })
            }
        }
    };
}
