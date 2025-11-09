//! CTAP2 client interface for FIDO2 authenticators
//!
//! This module provides both low-level and high-level APIs for communicating with
//! FIDO2 authenticators using the CTAP2 protocol.

mod requests;
mod types;

// Re-export public types
pub use requests::{GetAssertionRequest, MakeCredentialRequest};
pub use types::{
    ClientDataHash, CredentialDescriptor, CredentialType, PinUvAuth, PinUvAuthProtocol,
};

use crate::error::{Error, Result};

use keylib_sys::raw::{
    CborCommand as RawCborCommand, CborCommandResult as RawCborCommandResult,
    CborCommandStatus_CborCommandStatus_Fulfilled, CborCommandStatus_CborCommandStatus_Pending,
    CborCommandStatus_CborCommandStatus_Rejected, Transport as RawTransport,
    TransportList as RawTransportList, TransportType, cbor_authenticator_get_info,
    cbor_command_free, cbor_command_get_result, cbor_command_result_free, transport_close,
    transport_enumerate, transport_free, transport_get_description, transport_get_type,
    transport_list_free, transport_open, transport_read, transport_write,
};

use std::ffi::CStr;

/// Relying Party information for credential creation
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id: String,
    pub name: Option<String>,
}

/// User information for credential creation
#[derive(Debug, Clone)]
pub struct User {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: Option<String>,
}

/// Safe Rust wrapper for Transport
pub struct Transport {
    raw: *mut RawTransport,
}

impl Transport {
    /// Open the transport for communication
    pub fn open(&mut self) -> Result<()> {
        let result = unsafe { transport_open(self.raw) };
        if result != 0 {
            return Err(Error::Other);
        }
        Ok(())
    }

    /// Close the transport
    pub fn close(&mut self) {
        unsafe { transport_close(self.raw) };
    }

    /// Write data to the transport
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let result = unsafe {
            transport_write(
                self.raw,
                data.as_ptr() as *const ::std::os::raw::c_char,
                data.len(),
            )
        };
        if result != 0 {
            return Err(Error::Other);
        }
        Ok(())
    }

    /// Read data from the transport with timeout
    pub fn read(&mut self, buffer: &mut [u8], timeout_ms: i32) -> Result<usize> {
        let result = unsafe {
            transport_read(
                self.raw,
                buffer.as_mut_ptr() as *mut ::std::os::raw::c_char,
                buffer.len(),
                timeout_ms,
            )
        };
        if result < 0 {
            return Err(Error::Other);
        }
        Ok(result as usize)
    }

    /// Get the transport type
    pub fn get_type(&self) -> TransportType {
        unsafe { transport_get_type(self.raw) }
    }

    /// Get the raw transport handle (for internal use)
    pub fn raw_handle(&self) -> *mut RawTransport {
        self.raw
    }

    /// Get a description of the transport
    pub fn get_description(&self) -> Result<String> {
        let description_bytes = unsafe {
            let description = transport_get_description(self.raw);
            CStr::from_ptr(description).to_bytes()
        };
        let description_str = match std::str::from_utf8(description_bytes) {
            Ok(s) => s,
            Err(_) => return Err(Error::Other),
        };
        Ok(description_str.to_string())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        unsafe { transport_free(self.raw) };
    }
}

/// Safe Rust wrapper for TransportList
pub struct TransportList {
    raw: Option<*mut RawTransportList>,
}

impl TransportList {
    /// Enumerate all available transports
    pub fn enumerate() -> Result<Self> {
        let raw = unsafe { transport_enumerate() };
        Ok(TransportList {
            raw: if raw.is_null() { None } else { Some(raw) },
        })
    }

    /// Get the number of transports
    pub fn len(&self) -> usize {
        self.raw.map_or(0, |raw| unsafe { (*raw).count })
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a transport at the given index
    pub fn get(&self, index: usize) -> Option<Transport> {
        if index >= self.len() {
            return None;
        }
        let raw = self.raw?;
        let transport_ptr = unsafe { *(*raw).transports.add(index) };
        if transport_ptr.is_null() {
            return None;
        }
        Some(Transport { raw: transport_ptr })
    }

    /// Iterate over all transports
    pub fn iter(&self) -> TransportListIter<'_> {
        TransportListIter {
            list: self,
            index: 0,
        }
    }
}

impl Drop for TransportList {
    fn drop(&mut self) {
        if let Some(raw) = self.raw {
            unsafe { transport_list_free(raw) };
        }
    }
}

/// Iterator for TransportList
pub struct TransportListIter<'a> {
    list: &'a TransportList,
    index: usize,
}

impl<'a> Iterator for TransportListIter<'a> {
    type Item = Transport;

    fn next(&mut self) -> Option<Self::Item> {
        let transport = self.list.get(self.index);
        if transport.is_some() {
            self.index += 1;
        }
        transport
    }
}

/// Safe Rust wrapper for CborCommand
pub struct CborCommand {
    raw: *mut RawCborCommand,
}

impl CborCommand {
    /// Get the result of the CBOR command with timeout
    pub fn get_result(&mut self, timeout_ms: i32) -> Result<CborCommandResult> {
        let result_raw = unsafe { cbor_command_get_result(self.raw, timeout_ms) };
        if result_raw.is_null() {
            return Err(Error::Timeout);
        }
        Ok(CborCommandResult { raw: result_raw })
    }
}

impl Drop for CborCommand {
    fn drop(&mut self) {
        unsafe { cbor_command_free(self.raw) };
    }
}

/// Safe Rust wrapper for CborCommandResult
pub struct CborCommandResult {
    pub(crate) raw: *mut RawCborCommandResult,
}

impl CborCommandResult {
    /// Check if the command is still pending
    pub fn is_pending(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Pending }
    }

    /// Check if the command completed successfully
    pub fn is_fulfilled(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Fulfilled }
    }

    /// Check if the command failed
    pub fn is_rejected(&self) -> bool {
        unsafe { (*self.raw).status == CborCommandStatus_CborCommandStatus_Rejected }
    }

    /// Get the data if the command was fulfilled
    pub fn get_data(&self) -> Option<&[u8]> {
        if !self.is_fulfilled() {
            return None;
        }
        unsafe {
            let data_ptr: *mut std::os::raw::c_char = (*self.raw).result.data;
            if data_ptr.is_null() {
                return None;
            }
            Some(std::slice::from_raw_parts(
                data_ptr as *const u8,
                (*self.raw).data_len,
            ))
        }
    }

    /// Get the error code if the command was rejected
    pub fn get_error(&self) -> Option<i32> {
        if !self.is_rejected() {
            return None;
        }
        Some(unsafe { (*self.raw).result.error_code })
    }
}

impl Drop for CborCommandResult {
    fn drop(&mut self) {
        unsafe { cbor_command_result_free(self.raw) };
    }
}

/// Client for communicating with FIDO2 authenticators
pub struct Client;

impl Client {
    /// Enumerate all available transports
    pub fn enumerate_transports() -> Result<TransportList> {
        TransportList::enumerate()
    }

    /// Send authenticatorGetInfo command
    pub fn authenticator_get_info(transport: &mut Transport) -> Result<CborCommand> {
        let cmd_raw = unsafe { cbor_authenticator_get_info(transport.raw) };
        if cmd_raw.is_null() {
            return Err(Error::Other);
        }
        Ok(CborCommand { raw: cmd_raw })
    }

    /// Create a new credential (WebAuthn registration)
    ///
    /// Uses the builder pattern for type-safe, ergonomic credential creation.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `MakeCredentialRequest` built using the builder pattern
    ///
    /// # Returns
    ///
    /// The raw CBOR-encoded attestation object from the authenticator
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use keylib::*;
    /// # fn main() -> Result<()> {
    /// # let mut transport = client::TransportList::enumerate()?.get(0).unwrap();
    /// # transport.open()?;
    /// use sha2::{Digest, Sha256};
    /// use keylib::client::{MakeCredentialRequest, ClientDataHash, PinUvAuth, PinUvAuthProtocol};
    ///
    /// let client_data = b"...";
    /// let hash_bytes = Sha256::digest(client_data);
    /// let client_data_hash = ClientDataHash::from_slice(&hash_bytes)?;
    ///
    /// let rp = client::RelyingParty {
    ///     id: "example.com".to_string(),
    ///     name: Some("Example Corp".to_string()),
    /// };
    ///
    /// let user = client::User {
    ///     id: vec![1, 2, 3, 4],
    ///     name: "alice@example.com".to_string(),
    ///     display_name: Some("Alice".to_string()),
    /// };
    ///
    /// let pin_auth = PinUvAuth::new(vec![1, 2, 3], PinUvAuthProtocol::V2);
    /// let request = MakeCredentialRequest::new(client_data_hash, rp, user)
    ///     .with_pin_uv_auth(pin_auth)
    ///     .with_timeout(60000);
    ///
    /// let response = client::Client::make_credential(&mut transport, request)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn make_credential(
        transport: &mut Transport,
        request: MakeCredentialRequest,
    ) -> Result<Vec<u8>> {
        use ciborium::value::Value;

        // Build the CTAP2 authenticatorMakeCredential request
        let mut cbor_request = Vec::new();

        // 0x01: clientDataHash (required)
        cbor_request.push((
            Value::Integer(1.into()),
            Value::Bytes(request.client_data_hash.as_slice().to_vec()),
        ));

        // 0x02: rp (required)
        let mut rp_map = Vec::new();
        rp_map.push((
            Value::Text("id".to_string()),
            Value::Text(request.rp.id.clone()),
        ));
        if let Some(name) = &request.rp.name {
            rp_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        cbor_request.push((Value::Integer(2.into()), Value::Map(rp_map)));

        // 0x03: user (required)
        let mut user_map = Vec::new();
        user_map.push((
            Value::Text("id".to_string()),
            Value::Bytes(request.user.id.clone()),
        ));
        user_map.push((
            Value::Text("name".to_string()),
            Value::Text(request.user.name.clone()),
        ));
        if let Some(display_name) = &request.user.display_name {
            user_map.push((
                Value::Text("displayName".to_string()),
                Value::Text(display_name.clone()),
            ));
        }
        cbor_request.push((Value::Integer(3.into()), Value::Map(user_map)));

        // 0x04: pubKeyCredParams (required) - ES256 only for now
        let alg_param = vec![
            (Value::Text("alg".to_string()), Value::Integer((-7).into())),
            (
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ),
        ];
        cbor_request.push((
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(alg_param)]),
        ));

        // 0x07: options (optional)
        if request.resident_key.is_some() || request.user_verification.is_some() {
            let mut options_map = Vec::new();
            if let Some(rk) = request.resident_key {
                options_map.push((Value::Text("rk".to_string()), Value::Bool(rk)));
            }
            if let Some(uv) = request.user_verification {
                options_map.push((Value::Text("uv".to_string()), Value::Bool(uv)));
            }
            cbor_request.push((Value::Integer(7.into()), Value::Map(options_map)));
        }

        // 0x08: pinUvAuthParam (optional)
        // 0x09: pinUvAuthProtocol (optional)
        if let Some(pin_auth) = &request.pin_uv_auth {
            cbor_request.push((
                Value::Integer(8.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));
            cbor_request.push((
                Value::Integer(9.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor_data.push(0x01); // authenticatorMakeCredential command
        ciborium::into_writer(&Value::Map(cbor_request), &mut cbor_data)
            .map_err(|_| Error::Other)?;

        // Send the command
        transport.write(&cbor_data)?;

        // Read the response
        let mut buffer = vec![0u8; 7609]; // Max CTAP message size
        let response_len = transport.read(&mut buffer, request.timeout_ms)?;

        if response_len == 0 {
            return Err(Error::Other);
        }

        // Check status byte
        let status = buffer[0];
        if status != 0x00 {
            // Non-zero status means error
            return Err(Error::from(status as i32));
        }

        // Return the CBOR response (excluding status byte)
        Ok(buffer[1..response_len].to_vec())
    }

    /// Get an assertion (WebAuthn authentication)
    ///
    /// Uses the builder pattern for type-safe, ergonomic authentication.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport to communicate with the authenticator
    /// * `request` - A `GetAssertionRequest` built using the builder pattern
    ///
    /// # Returns
    ///
    /// The raw CBOR-encoded assertion response from the authenticator
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use keylib::*;
    /// # fn main() -> Result<()> {
    /// # let mut transport = client::TransportList::enumerate()?.get(0).unwrap();
    /// # transport.open()?;
    /// use sha2::{Digest, Sha256};
    /// use keylib::client::{GetAssertionRequest, ClientDataHash, CredentialDescriptor, PinUvAuth, PinUvAuthProtocol};
    ///
    /// let client_data = b"...";
    /// let hash_bytes = Sha256::digest(client_data);
    /// let client_data_hash = ClientDataHash::from_slice(&hash_bytes)?;
    ///
    /// let credential = CredentialDescriptor::public_key(vec![1, 2, 3, 4]);
    /// let pin_auth = PinUvAuth::new(vec![1, 2, 3], PinUvAuthProtocol::V2);
    ///
    /// let request = GetAssertionRequest::new(client_data_hash, "example.com")
    ///     .with_credential(credential)
    ///     .with_pin_uv_auth(pin_auth)
    ///     .with_timeout(60000);
    ///
    /// let response = client::Client::get_assertion(&mut transport, request)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_assertion(
        transport: &mut Transport,
        request: GetAssertionRequest,
    ) -> Result<Vec<u8>> {
        use ciborium::value::Value;

        // Build the CTAP2 authenticatorGetAssertion request
        let mut cbor_request = Vec::new();

        // 0x01: rpId (required)
        cbor_request.push((Value::Integer(1.into()), Value::Text(request.rp_id.clone())));

        // 0x02: clientDataHash (required)
        cbor_request.push((
            Value::Integer(2.into()),
            Value::Bytes(request.client_data_hash.as_slice().to_vec()),
        ));

        // 0x03: allowList (optional)
        if !request.allow_list.is_empty() {
            let mut cred_list = Vec::new();
            for cred in &request.allow_list {
                let cred_descriptor = vec![
                    (
                        Value::Text("type".to_string()),
                        Value::Text(cred.credential_type.as_str().to_string()),
                    ),
                    (Value::Text("id".to_string()), Value::Bytes(cred.id.clone())),
                ];
                cred_list.push(Value::Map(cred_descriptor));
            }
            cbor_request.push((Value::Integer(3.into()), Value::Array(cred_list)));
        }

        // 0x05: options (optional)
        if let Some(uv) = request.user_verification {
            let options_map = vec![(Value::Text("uv".to_string()), Value::Bool(uv))];
            cbor_request.push((Value::Integer(5.into()), Value::Map(options_map)));
        }

        // 0x06: pinUvAuthParam (optional)
        // 0x07: pinUvAuthProtocol (optional)
        if let Some(pin_auth) = &request.pin_uv_auth {
            cbor_request.push((
                Value::Integer(6.into()),
                Value::Bytes(pin_auth.param().to_vec()),
            ));
            cbor_request.push((
                Value::Integer(7.into()),
                Value::Integer(pin_auth.protocol_u8().into()),
            ));
        }

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor_data.push(0x02); // authenticatorGetAssertion command
        ciborium::into_writer(&Value::Map(cbor_request), &mut cbor_data)
            .map_err(|_| Error::Other)?;

        // Send the command
        transport.write(&cbor_data)?;

        // Read the response
        let mut buffer = vec![0u8; 7609]; // Max CTAP message size
        let response_len = transport.read(&mut buffer, request.timeout_ms)?;

        if response_len == 0 {
            return Err(Error::Other);
        }

        // Check status byte
        let status = buffer[0];
        if status != 0x00 {
            // Non-zero status means error
            return Err(Error::from(status as i32));
        }

        // Return the CBOR response (excluding status byte)
        Ok(buffer[1..response_len].to_vec())
    }
}
