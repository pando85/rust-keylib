//! Pure Rust PIN Protocol Support
//!
//! Provides PIN/UV authentication protocol implementation matching zig-ffi.

use crate::common::{Error, PinUvAuthProtocol, Result};
use crate::rust_impl::transport::Transport;

use keylib_crypto::pin_protocol;

use ciborium::value::Value;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use rand::rngs::OsRng;

/// PIN protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    /// PIN protocol version 1 (AES-256-CBC + HMAC-SHA-256)
    V1,
    /// PIN protocol version 2 (HMAC-SECRET)
    V2,
}

impl From<PinProtocol> for PinUvAuthProtocol {
    fn from(protocol: PinProtocol) -> Self {
        match protocol {
            PinProtocol::V1 => PinUvAuthProtocol::V1,
            PinProtocol::V2 => PinUvAuthProtocol::V2,
        }
    }
}

impl From<PinUvAuthProtocol> for PinProtocol {
    fn from(protocol: PinUvAuthProtocol) -> Self {
        match protocol {
            PinUvAuthProtocol::V1 => PinProtocol::V1,
            PinUvAuthProtocol::V2 => PinProtocol::V2,
        }
    }
}

/// PIN/UV authentication encapsulation
///
/// State machine for PIN protocol operations. Matches the API of zig-ffi.
pub struct PinUvAuthEncapsulation {
    protocol: PinProtocol,
    /// Platform's persistent key pair (for multiple operations)
    platform_secret: Option<Vec<u8>>,
    platform_public: Option<Vec<u8>>,
    /// Authenticator's public key (from getKeyAgreement)
    authenticator_key: Option<P256PublicKey>,
    /// Shared secret derived from ECDH
    shared_secret: Option<Vec<u8>>,
    /// PIN token (from getPinToken or getPinUvAuthTokenUsingPinWithPermissions)
    pin_token: Option<Vec<u8>>,
}

impl PinUvAuthEncapsulation {
    /// Create a new PIN/UV authentication encapsulation
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to use for initialization (performs key agreement)
    /// * `protocol` - The PIN protocol version to use
    pub fn new(transport: &mut Transport, protocol: PinProtocol) -> Result<Self> {
        let mut encap = Self {
            protocol,
            platform_secret: None,
            platform_public: None,
            authenticator_key: None,
            shared_secret: None,
            pin_token: None,
        };

        // Perform key agreement immediately
        encap.initialize(transport)?;

        Ok(encap)
    }

    /// Initialize the encapsulation by performing key agreement
    ///
    /// This sends clientPin subcommand 0x02 (getKeyAgreement) to the authenticator.
    pub fn initialize(&mut self, transport: &mut Transport) -> Result<()> {
        // Generate platform key pair (using SecretKey for persistence)
        let platform_secret_key = P256SecretKey::random(&mut OsRng);
        let platform_public_key = platform_secret_key.public_key();
        let platform_public_point = platform_public_key.to_encoded_point(false);

        // Store platform keys
        self.platform_secret = Some(platform_secret_key.to_bytes().to_vec());
        self.platform_public = Some(platform_public_point.as_bytes().to_vec());

        // Build getKeyAgreement request
        let mut request_map = Vec::new();
        request_map.push((
            Value::Integer(1.into()), // pinUvAuthProtocol
            Value::Integer(match self.protocol {
                PinProtocol::V1 => 1,
                PinProtocol::V2 => 2,
            }.into()),
        ));
        request_map.push((
            Value::Integer(2.into()), // subCommand (getKeyAgreement = 0x02)
            Value::Integer(0x02.into()),
        ));

        let mut request_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(request_map), &mut request_bytes)
            .map_err(|_| Error::Other)?;

        // Send clientPin command (0x06)
        let response = transport.send_ctap_command(0x06, &request_bytes)?;

        // Parse response to get authenticator's public key
        let response_value: Value = ciborium::de::from_reader(&response[..])
            .map_err(|_| Error::Other)?;

        // Extract keyAgreement from response (should be in response[0x01])
        let authenticator_cose_key = match response_value {
            Value::Map(map) => {
                map.iter()
                    .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 1.into()))
                    .and_then(|(_, v)| Some(v.clone()))
                    .ok_or(Error::Other)?
            }
            _ => return Err(Error::Other),
        };

        // Parse COSE key to get P-256 public key
        let authenticator_public_key = Self::parse_cose_key(&authenticator_cose_key)?;

        // Perform ECDH to derive shared secret
        use p256::ecdh::diffie_hellman;
        let shared_secret = diffie_hellman(
            platform_secret_key.to_nonzero_scalar(),
            authenticator_public_key.as_affine(),
        );
        let shared_secret_bytes = shared_secret.raw_secret_bytes().to_vec();

        // Store authenticator key and shared secret
        self.authenticator_key = Some(authenticator_public_key);
        self.shared_secret = Some(shared_secret_bytes);

        Ok(())
    }

    /// Get a PIN/UV auth token using PIN with permissions
    ///
    /// This is the recommended way to get a PIN token in CTAP 2.1.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `pin` - The user's PIN
    /// * `permissions` - Permission flags (0x01 = makeCredential, 0x02 = getAssertion, etc.)
    /// * `rp_id` - Optional RP ID to scope the permission
    pub fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        transport: &mut Transport,
        pin: &str,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        let shared_secret = self.shared_secret.as_ref().ok_or(Error::Other)?;

        // Encrypt PIN with shared secret
        let pin_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(pin.as_bytes());
            hasher.finalize().to_vec()
        };

        let pin_hash_enc = match self.protocol {
            PinProtocol::V1 => {
                // Derive encryption key for PIN protocol v1
                let (enc_key, _) = pin_protocol::v1::derive_keys(&shared_secret.as_slice().try_into().map_err(|_| Error::Other)?);
                pin_protocol::v1::encrypt(&enc_key, &pin_hash[..16])
                    .map_err(|_| Error::Other)?
            }
            PinProtocol::V2 => {
                // Derive encryption key for PIN protocol v2
                let enc_key = pin_protocol::v2::derive_encryption_key(&shared_secret.as_slice().try_into().map_err(|_| Error::Other)?);
                pin_protocol::v2::encrypt(&enc_key, &pin_hash[..16])
                    .map_err(|_| Error::Other)?
            }
        };

        // Get platform key agreement parameter
        let platform_key_agreement = self.get_key_agreement_cose()?;

        // Build getPinUvAuthTokenUsingPinWithPermissions request
        let mut request_map = Vec::new();
        request_map.push((
            Value::Integer(1.into()), // pinUvAuthProtocol
            Value::Integer(match self.protocol {
                PinProtocol::V1 => 1,
                PinProtocol::V2 => 2,
            }.into()),
        ));
        request_map.push((
            Value::Integer(2.into()), // subCommand (getPinUvAuthTokenUsingPinWithPermissions = 0x09)
            Value::Integer(0x09.into()),
        ));
        request_map.push((
            Value::Integer(3.into()), // keyAgreement
            platform_key_agreement,
        ));
        request_map.push((
            Value::Integer(6.into()), // pinHashEnc (0x06)
            Value::Bytes(pin_hash_enc),
        ));
        request_map.push((
            Value::Integer(9.into()), // permissions (0x09)
            Value::Integer(permissions.into()),
        ));
        if let Some(rp_id_str) = rp_id {
            request_map.push((
                Value::Integer(10.into()), // rpId (0x0A)
                Value::Text(rp_id_str.to_string()),
            ));
        }

        let mut request_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(request_map), &mut request_bytes)
            .map_err(|_| Error::Other)?;

        eprintln!("[DEBUG] Sending getPinUvAuthTokenUsingPinWithPermissions (subCommand=0x09)");
        eprintln!("[DEBUG] Request size: {} bytes", request_bytes.len());

        // Send clientPin command (0x06)
        let response = transport.send_ctap_command(0x06, &request_bytes).map_err(|e| {
            eprintln!("[DEBUG] getPinUvAuthTokenUsingPinWithPermissions failed with error: {:?}", e);
            e
        })?;

        eprintln!("[DEBUG] getPinUvAuthTokenUsingPinWithPermissions response: {} bytes", response.len());
        if response.len() > 0 {
            eprintln!("[DEBUG] Response bytes: {:02x?}", &response[..response.len().min(64)]);
        }

        // Parse response to get pinUvAuthToken
        let response_value: Value = ciborium::de::from_reader(&response[..])
            .map_err(|e| {
                eprintln!("[DEBUG] Failed to parse CBOR response: {:?}", e);
                Error::Other
            })?;

        eprintln!("[DEBUG] Parsed response value: {:?}", response_value);

        let pin_token_enc = match response_value {
            Value::Map(map) => {
                map.iter()
                    .find(|(k, _)| matches!(k, Value::Integer(i) if *i == 2.into()))
                    .and_then(|(_, v)| match v {
                        Value::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        eprintln!("[DEBUG] No pinUvAuthToken (key 2) found in response map");
                        Error::Other
                    })?
            }
            _ => {
                eprintln!("[DEBUG] Response is not a map");
                return Err(Error::Other);
            }
        };

        // Decrypt PIN token
        let pin_token = match self.protocol {
            PinProtocol::V1 => {
                let (enc_key, _) = pin_protocol::v1::derive_keys(&shared_secret.as_slice().try_into().map_err(|_| Error::Other)?);
                pin_protocol::v1::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?
            }
            PinProtocol::V2 => {
                let enc_key = pin_protocol::v2::derive_encryption_key(&shared_secret.as_slice().try_into().map_err(|_| Error::Other)?);
                pin_protocol::v2::decrypt(&enc_key, &pin_token_enc)
                    .map_err(|_| Error::Other)?
            }
        };

        // Store PIN token
        self.pin_token = Some(pin_token.clone());

        Ok(pin_token)
    }

    /// Calculate pinUvAuthParam for a request
    ///
    /// # Arguments
    ///
    /// * `data` - The data to authenticate (e.g., clientDataHash || rpIdHash for makeCredential)
    /// * `pin_token` - The PIN token obtained from get_pin_uv_auth_token_using_pin_with_permissions
    pub fn authenticate(&self, data: &[u8], pin_token: &[u8]) -> Result<Vec<u8>> {
        let pin_token_array: &[u8; 32] = pin_token.try_into().map_err(|_| Error::Other)?;
        let result = match self.protocol {
            PinProtocol::V1 => pin_protocol::v1::authenticate(pin_token_array, data).to_vec(),
            PinProtocol::V2 => pin_protocol::v2::authenticate(pin_token_array, data).to_vec(),
        };

        Ok(result)
    }

    /// Get the platform's key agreement parameter in COSE format
    fn get_key_agreement_cose(&self) -> Result<Value> {
        let secret_bytes = self.platform_secret.as_ref().ok_or(Error::Other)?;
        let secret_key = P256SecretKey::from_bytes(secret_bytes.as_slice().into())
            .map_err(|_| Error::Other)?;
        let public_key = secret_key.public_key();
        let point = public_key.to_encoded_point(false);

        let mut key_map = Vec::new();
        key_map.push((Value::Integer(1.into()), Value::Integer(2.into()))); // kty: EC2
        key_map.push((Value::Integer(3.into()), Value::Integer((-25).into()))); // alg: ECDH-ES+HKDF-256
        key_map.push((Value::Integer((-1).into()), Value::Integer(1.into()))); // crv: P-256
        key_map.push((
            Value::Integer((-2).into()),
            Value::Bytes(point.x().ok_or(Error::Other)?.to_vec()),
        )); // x
        key_map.push((
            Value::Integer((-3).into()),
            Value::Bytes(point.y().ok_or(Error::Other)?.to_vec()),
        )); // y

        Ok(Value::Map(key_map))
    }

    /// Parse a COSE key to extract P-256 public key
    fn parse_cose_key(cose_key: &Value) -> Result<P256PublicKey> {
        let map = match cose_key {
            Value::Map(m) => m,
            _ => return Err(Error::Other),
        };

        // Extract x and y coordinates
        let x = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == (-2).into()))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or(Error::Other)?;

        let y = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if *i == (-3).into()))
            .and_then(|(_, v)| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or(Error::Other)?;

        // Create uncompressed SEC1 encoding: 0x04 || x || y
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);

        // Parse as P-256 public key
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        let point = p256::EncodedPoint::from_bytes(&uncompressed)
            .map_err(|_| Error::Other)?;

        // CtOption::into() returns Option
        let public_key: Option<P256PublicKey> = P256PublicKey::from_encoded_point(&point).into();
        public_key.ok_or(Error::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_protocol_conversion() {
        assert_eq!(PinProtocol::from(PinUvAuthProtocol::V1), PinProtocol::V1);
        assert_eq!(PinProtocol::from(PinUvAuthProtocol::V2), PinProtocol::V2);
    }
}
