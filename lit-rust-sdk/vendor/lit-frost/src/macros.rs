macro_rules! serde_impl {
    ($name:ident, $method_length:ident, $len:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    (self.scheme, hex::encode(&self.value[..])).serialize(s)
                } else {
                    use serde::ser::SerializeTuple;

                    let mut seq = s.serialize_tuple(self.value.len() + 1)?;
                    seq.serialize_element(&(self.scheme as u8))?;
                    for b in &self.value {
                        seq.serialize_element(b)?;
                    }

                    seq.end()
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    let (ty, value) = <(String, String)>::deserialize(d)?;
                    let scheme: Scheme = ty
                        .parse()
                        .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
                    let value = hex::decode(&value)
                        .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
                    Ok(Self { scheme, value })
                } else {
                    struct NameVisitor;

                    impl<'de> serde::de::Visitor<'de> for NameVisitor {
                        type Value = $name;

                        fn expecting(
                            &self,
                            formatter: &mut std::fmt::Formatter<'_>,
                        ) -> std::fmt::Result {
                            formatter.write_str("a tuple of (u8, Vec<u8>)")
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                        where
                            A: serde::de::SeqAccess<'de>,
                        {
                            let scheme: Scheme = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| serde::de::Error::custom("Missing scheme"))?
                                .try_into()
                                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
                            let length = scheme
                                .$method_length()
                                .map_err(|e| serde::de::Error::custom(e.to_string()))?;
                            let mut value = Vec::new();
                            while let Some(b) = seq.next_element::<u8>()? {
                                value.push(b);
                                if value.len() == length {
                                    break;
                                }
                            }
                            if value.len() != length {
                                return Err(serde::de::Error::custom("Invalid length"));
                            }
                            Ok($name { scheme, value })
                        }
                    }

                    d.deserialize_tuple($len, NameVisitor)
                }
            }
        }
    };
}

macro_rules! display_impl {
    ($name:ident) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "scheme: {}: value: 0x", self.scheme)?;
                for b in &self.value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    };
}

macro_rules! ct_is_zero_impl {
    () => {
        /// Returns true if this value is zero.
        pub fn is_zero(&self) -> subtle::Choice {
            crate::is_zero(self.value.as_slice())
        }
    };
}

macro_rules! is_identity_impl {
    () => {
        /// Returns true if this value is zero.
        pub fn is_identity(&self) -> subtle::Choice {
            if self.value.iter().all(|x| *x == 0) {
                subtle::Choice::from(1u8)
            } else {
                subtle::Choice::from(0u8)
            }
        }
    };
}

macro_rules! from_bytes_impl {
    ($name:ident) => {
        impl From<&$name> for Vec<u8> {
            fn from(value: &$name) -> Self {
                serde_bare::to_vec(value).unwrap()
            }
        }

        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                Self::from(&value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<&Vec<u8>> for $name {
            type Error = Error;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<Box<[u8]>> for $name {
            type Error = Error;

            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                serde_bare::from_slice(value).map_err(|e| Error::General(e.to_string()))
            }
        }
    };
}

macro_rules! try_from_scheme_ref {
    ($path:path, $name:ident, $op:expr) => {
        impl TryFrom<$name> for $path {
            type Error = Error;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl TryFrom<&$name> for $path {
            type Error = Error;

            fn try_from(value: &$name) -> Result<Self, Self::Error> {
                $op(value)
            }
        }
    };
    ($name:ident, $path:path, $op:expr) => {
        impl TryFrom<(Scheme, $path)> for $name {
            type Error = Error;

            fn try_from((scheme, value): (Scheme, $path)) -> Result<Self, Self::Error> {
                Self::try_from((scheme, &value))
            }
        }

        impl TryFrom<(Scheme, &$path)> for $name {
            type Error = Error;

            fn try_from((scheme, value): (Scheme, &$path)) -> Result<Self, Self::Error> {
                $op(scheme, value)
            }
        }
    };
}
