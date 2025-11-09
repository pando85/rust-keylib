//! Type-safe wrappers for CTAP2 client operations

use crate::error::{Error, Result};

/// A validated client data hash (must be exactly 32 bytes)
///
/// This newtype ensures that client data hashes are always the correct length,
/// preventing runtime validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDataHash([u8; 32]);

impl ClientDataHash {
    /// Create a new ClientDataHash from a 32-byte array
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::ClientDataHash;
    /// let hash = [0u8; 32];
    /// let client_data_hash = ClientDataHash::new(hash);
    /// ```
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Create a ClientDataHash from a slice
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidClientDataHash` if the slice is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::ClientDataHash;
    /// # fn main() -> keylib::Result<()> {
    /// let hash_slice = &[0u8; 32][..];
    /// let client_data_hash = ClientDataHash::from_slice(hash_slice)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidClientDataHash);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(slice);
        Ok(Self(hash))
    }

    /// Get a reference to the underlying hash bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the hash as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ClientDataHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ClientDataHash {
    fn from(hash: [u8; 32]) -> Self {
        Self::new(hash)
    }
}

/// Type of credential
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// Public key credential (the only type currently defined in CTAP2)
    #[default]
    PublicKey,
}

impl CredentialType {
    /// Get the string representation for CBOR encoding
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::PublicKey => "public-key",
        }
    }
}

/// A credential descriptor identifying a specific credential
///
/// Used in getAssertion to specify which credentials are allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// The credential ID
    pub id: Vec<u8>,
    /// The type of credential (typically PublicKey)
    pub credential_type: CredentialType,
}

impl CredentialDescriptor {
    /// Create a new credential descriptor
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{CredentialDescriptor, CredentialType};
    /// let descriptor = CredentialDescriptor::new(
    ///     vec![1, 2, 3, 4],
    ///     CredentialType::PublicKey,
    /// );
    /// ```
    pub fn new(id: Vec<u8>, credential_type: CredentialType) -> Self {
        Self {
            id,
            credential_type,
        }
    }

    /// Create a public key credential descriptor (convenience method)
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::CredentialDescriptor;
    /// let descriptor = CredentialDescriptor::public_key(vec![1, 2, 3, 4]);
    /// ```
    pub fn public_key(id: Vec<u8>) -> Self {
        Self {
            id,
            credential_type: CredentialType::PublicKey,
        }
    }
}

/// PIN/UV authentication protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PinUvAuthProtocol {
    /// PIN/UV protocol version 1
    V1 = 1,
    /// PIN/UV protocol version 2 (recommended)
    V2 = 2,
}

impl PinUvAuthProtocol {
    /// Convert to u8 for CBOR encoding
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<PinUvAuthProtocol> for u8 {
    fn from(protocol: PinUvAuthProtocol) -> u8 {
        protocol.as_u8()
    }
}

/// Bundle of PIN/UV authentication parameter and protocol version
///
/// This ensures that the auth parameter and protocol version are always paired correctly.
#[derive(Debug, Clone)]
pub struct PinUvAuth {
    param: Vec<u8>,
    protocol: PinUvAuthProtocol,
}

impl PinUvAuth {
    /// Create a new PIN/UV authentication bundle
    ///
    /// # Arguments
    ///
    /// * `param` - The authentication parameter bytes
    /// * `protocol` - The protocol version used to generate the parameter
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{PinUvAuth, PinUvAuthProtocol};
    /// let pin_auth = PinUvAuth::new(
    ///     vec![1, 2, 3, 4],
    ///     PinUvAuthProtocol::V2,
    /// );
    /// ```
    pub fn new(param: Vec<u8>, protocol: PinUvAuthProtocol) -> Self {
        Self { param, protocol }
    }

    /// Get the authentication parameter bytes
    pub fn param(&self) -> &[u8] {
        &self.param
    }

    /// Get the protocol version
    pub fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }

    /// Get the protocol version as u8
    pub fn protocol_u8(&self) -> u8 {
        self.protocol.as_u8()
    }
}
