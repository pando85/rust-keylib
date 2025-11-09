use crate::client::Transport;
use crate::error::{Error, Result};
use keylib_sys::raw::*;

/// PIN protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    /// PIN protocol version 1
    V1 = 1,
    /// PIN protocol version 2 (for FIPS certified authenticators)
    V2 = 2,
}

/// PIN/UV authentication protocol encapsulation
///
/// This wraps the underlying C implementation of PIN protocol handling,
/// which includes ECDH key agreement, encryption, and token retrieval.
pub struct PinUvAuthEncapsulation {
    raw: *mut std::ffi::c_void,
    #[allow(dead_code)]
    protocol_version: PinProtocol,
}

impl PinUvAuthEncapsulation {
    /// Establish shared secret with authenticator
    ///
    /// This performs ECDH key agreement with the authenticator to establish
    /// a shared secret for encrypting PIN data and authentication tokens.
    ///
    /// # Arguments
    /// * `transport` - Active transport connection to authenticator
    /// * `protocol` - PIN protocol version to use (V1 or V2)
    ///
    /// # Returns
    /// A new encapsulation instance with established shared secret
    ///
    /// # Errors
    /// Returns an error if:
    /// - Key agreement command fails
    /// - ECDH computation fails
    /// - Authenticator returns invalid public key
    pub fn new(transport: &mut Transport, protocol: PinProtocol) -> Result<Self> {
        let protocol_byte = match protocol {
            PinProtocol::V1 => 1,
            PinProtocol::V2 => 2,
        };

        let raw = unsafe {
            client_pin_encapsulation_new(transport.raw_handle() as *mut _, protocol_byte)
        };

        if raw.is_null() {
            return Err(Error::Other);
        }

        Ok(Self {
            raw,
            protocol_version: protocol,
        })
    }

    /// Get the platform's public key (for debugging/testing)
    ///
    /// Returns the 65-byte uncompressed P-256 public key (0x04 || x || y)
    ///
    /// # Errors
    /// Returns an error if the operation fails
    pub fn get_platform_public_key(&self) -> Result<[u8; 65]> {
        let mut public_key = [0u8; 65];
        let result = unsafe {
            client_pin_encapsulation_get_platform_key(self.raw as *const _, public_key.as_mut_ptr())
        };

        if result != 0 {
            return Err(Error::Other);
        }

        Ok(public_key)
    }

    /// Get a PIN token
    ///
    /// Retrieves a PIN token from the authenticator by encrypting the PIN hash
    /// with the shared secret and sending it to the authenticator.
    ///
    /// # Arguments
    /// * `transport` - Active transport connection
    /// * `pin` - User's PIN as a string
    ///
    /// # Returns
    /// Decrypted PIN token as a byte vector
    ///
    /// # Errors
    /// Returns an error if:
    /// - PIN is invalid
    /// - Encryption fails
    /// - Authenticator rejects the request
    /// - Decryption of response fails
    pub fn get_pin_token(&mut self, transport: &mut Transport, pin: &str) -> Result<Vec<u8>> {
        let pin_bytes = pin.as_bytes();
        let mut token_ptr: *mut u8 = std::ptr::null_mut();
        let mut token_len: usize = 0;

        let result = unsafe {
            client_pin_get_pin_token(
                transport.raw_handle() as *mut _,
                self.raw,
                pin_bytes.as_ptr(),
                pin_bytes.len(),
                &mut token_ptr,
                &mut token_len,
            )
        };

        if result != 0 {
            return Err(Error::Other);
        }

        if token_ptr.is_null() || token_len == 0 {
            return Err(Error::Other);
        }

        // Copy token data and free the C-allocated buffer
        let token = unsafe {
            let slice = std::slice::from_raw_parts(token_ptr, token_len);
            let vec = slice.to_vec();
            client_pin_free_token(token_ptr, token_len);
            vec
        };

        Ok(token)
    }

    /// Get PIN/UV token with permissions (CTAP 2.1+)
    ///
    /// Retrieves a PIN/UV token with specific permissions from the authenticator.
    /// This is required for CTAP 2.1+ operations.
    ///
    /// # Arguments
    /// * `transport` - Active transport connection
    /// * `pin` - User's PIN as a string
    /// * `permissions` - Permission bitmap (mc=1, ga=2, cm=4, be=8, lbw=16, acfg=32)
    /// * `rp_id` - Optional RP ID to scope the token
    ///
    /// # Returns
    /// PIN/UV token with specified permissions
    ///
    /// # Errors
    /// Returns an error if the operation fails or is not supported
    pub fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        transport: &mut Transport,
        pin: &str,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        let pin_bytes = pin.as_bytes();
        let mut token_ptr: *mut u8 = std::ptr::null_mut();
        let mut token_len: usize = 0;

        let (rp_id_ptr, rp_id_len) = match rp_id {
            Some(id) => (id.as_ptr(), id.len()),
            None => (std::ptr::null(), 0),
        };

        let result = unsafe {
            client_pin_get_pin_uv_auth_token_using_pin_with_permissions(
                transport.raw_handle() as *mut _,
                self.raw,
                pin_bytes.as_ptr(),
                pin_bytes.len(),
                permissions,
                rp_id_ptr,
                rp_id_len,
                &mut token_ptr,
                &mut token_len,
            )
        };

        if result != 0 {
            return Err(Error::Other);
        }

        if token_ptr.is_null() || token_len == 0 {
            return Err(Error::Other);
        }

        // Copy token data and free the C-allocated buffer
        let token = unsafe {
            let slice = std::slice::from_raw_parts(token_ptr, token_len);
            let vec = slice.to_vec();
            client_pin_free_token(token_ptr, token_len);
            vec
        };

        Ok(token)
    }

    /// Get PIN/UV token using UV with permissions (CTAP 2.1+)
    ///
    /// Retrieves a PIN/UV token using user verification (biometric, etc.)
    /// with specific permissions.
    ///
    /// # Arguments
    /// * `transport` - Active transport connection
    /// * `permissions` - Permission bitmap
    /// * `rp_id` - Optional RP ID to scope the token
    ///
    /// # Returns
    /// PIN/UV token with specified permissions
    ///
    /// # Errors
    /// Returns an error if the operation fails or is not supported
    pub fn get_pin_uv_auth_token_using_uv_with_permissions(
        &mut self,
        transport: &mut Transport,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut token_ptr: *mut u8 = std::ptr::null_mut();
        let mut token_len: usize = 0;

        let (rp_id_ptr, rp_id_len) = match rp_id {
            Some(id) => (id.as_ptr(), id.len()),
            None => (std::ptr::null(), 0),
        };

        let result = unsafe {
            client_pin_get_pin_uv_auth_token_using_uv_with_permissions(
                transport.raw_handle() as *mut _,
                self.raw,
                permissions,
                rp_id_ptr,
                rp_id_len,
                &mut token_ptr,
                &mut token_len,
            )
        };

        if result != 0 {
            return Err(Error::Other);
        }

        if token_ptr.is_null() || token_len == 0 {
            return Err(Error::Other);
        }

        // Copy token data and free the C-allocated buffer
        let token = unsafe {
            let slice = std::slice::from_raw_parts(token_ptr, token_len);
            let vec = slice.to_vec();
            client_pin_free_token(token_ptr, token_len);
            vec
        };

        Ok(token)
    }

    /// Compute PIN/UV auth parameter for a message
    ///
    /// This creates an HMAC-SHA-256 authentication tag over the provided message
    /// using the PIN/UV token as the key. The result is used to authenticate
    /// commands like makeCredential or getAssertion.
    ///
    /// # Arguments
    /// * `message` - The message to authenticate (typically clientDataHash)
    /// * `pin_uv_token` - The PIN/UV authentication token
    ///
    /// # Returns
    /// For PIN Protocol V1: First 16 bytes of HMAC-SHA-256(pin_uv_token, message)
    /// For PIN Protocol V2: Full 32 bytes of HMAC-SHA-256(pin_uv_token, message)
    ///
    /// # Example
    /// ```no_run
    /// # use keylib::*;
    /// # fn main() -> Result<()> {
    /// # let mut transport = client::TransportList::enumerate()?.get(0).unwrap();
    /// # transport.open()?;
    /// # let mut encap = client_pin::PinUvAuthEncapsulation::new(&mut transport, client_pin::PinProtocol::V2)?;
    /// # let pin_token = vec![0u8; 32];
    /// use sha2::{Digest, Sha256};
    ///
    /// let client_data_hash = Sha256::digest(b"client data");
    /// let auth_param = encap.authenticate(&client_data_hash, &pin_token)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn authenticate(&self, message: &[u8], pin_uv_token: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(pin_uv_token).map_err(|_| Error::Other)?;
        mac.update(message);
        let result = mac.finalize();

        // Per CTAP 2.1 spec:
        // V1: authenticate returns first 16 bytes of HMAC-SHA-256
        // V2: authenticate returns full 32 bytes of HMAC-SHA-256
        match self.protocol_version {
            PinProtocol::V1 => Ok(result.into_bytes()[..16].to_vec()),
            PinProtocol::V2 => Ok(result.into_bytes()[..32].to_vec()),
        }
    }
}

impl Drop for PinUvAuthEncapsulation {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                client_pin_encapsulation_free(self.raw);
            }
        }
    }
}

// Ensure the encapsulation can be safely sent between threads
unsafe impl Send for PinUvAuthEncapsulation {}
unsafe impl Sync for PinUvAuthEncapsulation {}
