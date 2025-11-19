//! CBOR encoding and decoding for CTAP protocol
//!
//! This module handles CBOR serialization/deserialization for CTAP requests and responses.
//! CTAP uses CBOR (RFC 8949) for all command and response data.

use crate::status::{Result, StatusCode};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ciborium::Value;
use serde::{Deserialize, Serialize};

/// Encode a value to CBOR bytes
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer).map_err(|_| StatusCode::InvalidCbor)?;
    Ok(buffer)
}

/// Decode CBOR bytes to a value
pub fn decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data).map_err(|_| StatusCode::InvalidCbor)
}

/// Encode value to CBOR Value for manual map construction
pub fn to_value<T: Serialize>(value: &T) -> Result<Value> {
    ciborium::value::Value::serialized(value).map_err(|_| StatusCode::InvalidCbor)
}

/// Decode CBOR Value to typed value
pub fn from_value<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T> {
    ciborium::value::Value::deserialized(&value).map_err(|_| StatusCode::InvalidCbor)
}

/// Build a CBOR map with integer keys (common in CTAP)
pub struct MapBuilder {
    entries: Vec<(i32, Value)>,
}

impl MapBuilder {
    /// Create a new map builder
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert an integer key and value
    pub fn insert<T: Serialize>(mut self, key: i32, value: T) -> Result<Self> {
        let val_val = to_value(&value)?;
        self.entries.push((key, val_val));
        Ok(self)
    }

    /// Insert an optional value (only if Some)
    pub fn insert_opt<T: Serialize>(mut self, key: i32, value: Option<T>) -> Result<Self> {
        if let Some(v) = value {
            let val_val = to_value(&v)?;
            self.entries.push((key, val_val));
        }
        Ok(self)
    }

    /// Insert bytes directly (avoids array serialization)
    pub fn insert_bytes(mut self, key: i32, bytes: &[u8]) -> Result<Self> {
        self.entries.push((key, Value::Bytes(bytes.to_vec())));
        Ok(self)
    }

    /// Build the map and encode to CBOR bytes
    pub fn build(self) -> Result<Vec<u8>> {
        let map: Vec<(Value, Value)> = self
            .entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();
        encode(&Value::Map(map))
    }

    /// Build the map as a CBOR Value
    pub fn build_value(self) -> Value {
        let map: Vec<(Value, Value)> = self
            .entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();
        Value::Map(map)
    }
}

impl Default for MapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a CBOR map with integer keys
pub struct MapParser {
    map: BTreeMap<i128, Value>,
}

impl MapParser {
    /// Parse from CBOR bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let value: Value =
            ciborium::from_reader(data).map_err(|_| StatusCode::InvalidCbor)?;

        Self::from_value(value)
    }

    /// Parse from a CBOR Value
    pub fn from_value(value: Value) -> Result<Self> {
        match value {
            Value::Map(pairs) => {
                let mut map = BTreeMap::new();
                for (k, v) in pairs {
                    if let Value::Integer(int_key) = k {
                        map.insert(int_key.into(), v);
                    } else {
                        return Err(StatusCode::InvalidCbor);
                    }
                }
                Ok(Self { map })
            }
            _ => Err(StatusCode::InvalidCbor),
        }
    }

    /// Get a required value by key
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: i32) -> Result<T> {
        let value = self
            .map
            .get(&(key as i128))
            .ok_or(StatusCode::MissingParameter)?;

        from_value(value.clone())
    }

    /// Get an optional value by key
    pub fn get_opt<T: for<'de> Deserialize<'de>>(&self, key: i32) -> Result<Option<T>> {
        match self.map.get(&(key as i128)) {
            Some(value) => Ok(Some(from_value(value.clone())?)),
            None => Ok(None),
        }
    }

    /// Check if a key exists
    pub fn contains_key(&self, key: i32) -> bool {
        self.map.contains_key(&(key as i128))
    }

    /// Get raw value for debugging
    pub fn get_raw(&self, key: i32) -> Option<&Value> {
        self.map.get(&(key as i128))
    }

    /// Get bytes directly (for CBOR Bytes type)
    ///
    /// This is needed because Value::Bytes doesn't automatically deserialize
    /// to Vec<u8> via the generic get() method.
    pub fn get_bytes(&self, key: i32) -> Result<Vec<u8>> {
        let value = self
            .map
            .get(&(key as i128))
            .ok_or(StatusCode::MissingParameter)?;

        match value {
            Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(StatusCode::InvalidCbor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_string() {
        let original = "Hello, CTAP!";
        let encoded = encode(&original).unwrap();
        let decoded: String = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_integer() {
        let original = 42i32;
        let encoded = encode(&original).unwrap();
        let decoded: i32 = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_bytes() {
        let original = vec![1u8, 2, 3, 4, 5];
        let encoded = encode(&original).unwrap();
        let decoded: Vec<u8> = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_map_builder() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .insert(2, 42i32)
            .unwrap()
            .insert(3, vec![1u8, 2, 3])
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let s: String = parser.get(1).unwrap();
        let i: i32 = parser.get(2).unwrap();
        let b: Vec<u8> = parser.get(3).unwrap();

        assert_eq!(s, "test");
        assert_eq!(i, 42);
        assert_eq!(b, vec![1u8, 2, 3]);
    }

    #[test]
    fn test_map_builder_optional() {
        let cbor = MapBuilder::new()
            .insert(1, "required")
            .unwrap()
            .insert_opt(2, Some(42i32))
            .unwrap()
            .insert_opt::<i32>(3, None)
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        assert!(parser.contains_key(1));
        assert!(parser.contains_key(2));
        assert!(!parser.contains_key(3));
    }

    #[test]
    fn test_map_parser_missing_key() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let result: Result<String> = parser.get(99);
        assert_eq!(result.unwrap_err(), StatusCode::MissingParameter);
    }

    #[test]
    fn test_map_parser_optional() {
        let cbor = MapBuilder::new()
            .insert(1, "test")
            .unwrap()
            .build()
            .unwrap();

        let parser = MapParser::from_bytes(&cbor).unwrap();
        let opt: Option<String> = parser.get_opt(99).unwrap();
        assert_eq!(opt, None);

        let opt: Option<String> = parser.get_opt(1).unwrap();
        assert_eq!(opt, Some("test".to_string()));
    }

    #[test]
    fn test_invalid_cbor() {
        let bad_data = vec![0xff, 0xff, 0xff];
        let result: Result<String> = decode(&bad_data);
        assert_eq!(result.unwrap_err(), StatusCode::InvalidCbor);
    }

    #[test]
    fn test_to_from_value() {
        let original = 42i32;
        let value = to_value(&original).unwrap();
        let decoded: i32 = from_value(value).unwrap();
        assert_eq!(original, decoded);
    }
}
