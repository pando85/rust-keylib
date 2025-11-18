//! Pure Rust Authenticator Implementation
//!
//! Provides a high-level interface matching the zig-ffi Authenticator API.

use crate::common::{Credential, CredentialRef, Error, Result};

#[cfg(feature = "pure-rust")]
use keylib_ctap::{
    authenticator::{Authenticator as CtapAuthenticator, AuthenticatorConfig as CtapConfig},
    callbacks::{
        CredentialStorageCallbacks, UpResult as CtapUpResult,
        UserInteractionCallbacks, UvResult as CtapUvResult,
    },
    types::Credential as CtapCredential,
    CommandDispatcher, StatusCode,
};

#[cfg(feature = "pure-rust")]
use std::sync::{Arc, Mutex};

/// User presence result (matches zig-ffi)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpResult {
    Denied,
    Accepted,
    Timeout,
}

#[cfg(feature = "pure-rust")]
impl From<UpResult> for CtapUpResult {
    fn from(result: UpResult) -> Self {
        match result {
            UpResult::Denied => CtapUpResult::Denied,
            UpResult::Accepted => CtapUpResult::Accepted,
            UpResult::Timeout => CtapUpResult::Timeout,
        }
    }
}

#[cfg(feature = "pure-rust")]
impl From<CtapUpResult> for UpResult {
    fn from(result: CtapUpResult) -> Self {
        match result {
            CtapUpResult::Denied => UpResult::Denied,
            CtapUpResult::Accepted => UpResult::Accepted,
            CtapUpResult::Timeout => UpResult::Timeout,
        }
    }
}

/// User verification result (matches zig-ffi)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvResult {
    Denied,
    Accepted,
    AcceptedWithUp,
    Timeout,
}

#[cfg(feature = "pure-rust")]
impl From<UvResult> for CtapUvResult {
    fn from(result: UvResult) -> Self {
        match result {
            UvResult::Denied => CtapUvResult::Denied,
            UvResult::Accepted => CtapUvResult::Accepted,
            UvResult::AcceptedWithUp => CtapUvResult::AcceptedWithUp,
            UvResult::Timeout => CtapUvResult::Timeout,
        }
    }
}

#[cfg(feature = "pure-rust")]
impl From<CtapUvResult> for UvResult {
    fn from(result: CtapUvResult) -> Self {
        match result {
            CtapUvResult::Denied => UvResult::Denied,
            CtapUvResult::Accepted => UvResult::Accepted,
            CtapUvResult::AcceptedWithUp => UvResult::AcceptedWithUp,
            CtapUvResult::Timeout => UvResult::Timeout,
        }
    }
}

/// User presence callback type
pub type UpCallback =
    Arc<dyn Fn(&str, Option<&str>, Option<&str>) -> Result<UpResult> + Send + Sync>;

/// User verification callback type
pub type UvCallback =
    Arc<dyn Fn(&str, Option<&str>, Option<&str>) -> Result<UvResult> + Send + Sync>;

/// Select callback type for choosing which user to authenticate with
pub type SelectCallback = Arc<dyn Fn(&str, &[String]) -> Result<usize> + Send + Sync>;

/// Write callback type for storing credential data
pub type WriteCallback = Arc<dyn Fn(CredentialRef) -> Result<()> + Send + Sync>;

/// Delete callback type for removing credential data
pub type DeleteCallback = Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// Read credentials callback type
pub type ReadCredentialsCallback =
    Arc<dyn Fn(&str, Option<&[u8]>) -> Result<Vec<Credential>> + Send + Sync>;

/// Get credential callback type
pub type GetCredentialCallback = Arc<dyn Fn(&[u8]) -> Result<Credential> + Send + Sync>;

/// Callback wrapper (matches zig-ffi Callbacks API)
#[derive(Clone, Default)]
pub struct Callbacks {
    pub up: Option<UpCallback>,
    pub uv: Option<UvCallback>,
    pub select: Option<SelectCallback>,
    pub write: Option<WriteCallback>,
    pub delete: Option<DeleteCallback>,
    pub read_credentials: Option<ReadCredentialsCallback>,
    pub get_credential: Option<GetCredentialCallback>,
}

/// Builder for creating Callbacks instances
#[derive(Default)]
pub struct CallbacksBuilder {
    up: Option<UpCallback>,
    uv: Option<UvCallback>,
    select: Option<SelectCallback>,
    write: Option<WriteCallback>,
    delete: Option<DeleteCallback>,
    read_credentials: Option<ReadCredentialsCallback>,
    get_credential: Option<GetCredentialCallback>,
}

impl CallbacksBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn up(mut self, callback: UpCallback) -> Self {
        self.up = Some(callback);
        self
    }

    pub fn uv(mut self, callback: UvCallback) -> Self {
        self.uv = Some(callback);
        self
    }

    pub fn select(mut self, callback: SelectCallback) -> Self {
        self.select = Some(callback);
        self
    }

    pub fn write(mut self, callback: WriteCallback) -> Self {
        self.write = Some(callback);
        self
    }

    pub fn delete(mut self, callback: DeleteCallback) -> Self {
        self.delete = Some(callback);
        self
    }

    pub fn read_credentials(mut self, callback: ReadCredentialsCallback) -> Self {
        self.read_credentials = Some(callback);
        self
    }

    pub fn get_credential(mut self, callback: GetCredentialCallback) -> Self {
        self.get_credential = Some(callback);
        self
    }

    pub fn build(self) -> Callbacks {
        Callbacks {
            up: self.up,
            uv: self.uv,
            select: self.select,
            write: self.write,
            delete: self.delete,
            read_credentials: self.read_credentials,
            get_credential: self.get_credential,
        }
    }
}

/// Callback adapter that implements keylib-ctap traits
#[cfg(feature = "pure-rust")]
struct CallbackAdapter {
    callbacks: Callbacks,
}

#[cfg(feature = "pure-rust")]
impl UserInteractionCallbacks for CallbackAdapter {
    fn request_up(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> keylib_ctap::Result<CtapUpResult> {
        if let Some(up_cb) = &self.callbacks.up {
            let result = up_cb(info, user_name, Some(rp_id)).map_err(|_| StatusCode::Other)?;
            Ok(result.into())
        } else {
            Ok(CtapUpResult::Accepted) // Default to accepted
        }
    }

    fn request_uv(
        &self,
        info: &str,
        user_name: Option<&str>,
        rp_id: &str,
    ) -> keylib_ctap::Result<CtapUvResult> {
        if let Some(uv_cb) = &self.callbacks.uv {
            let result = uv_cb(info, user_name, Some(rp_id)).map_err(|_| StatusCode::Other)?;
            Ok(result.into())
        } else {
            Ok(CtapUvResult::Accepted) // Default to accepted
        }
    }

    fn select_credential(&self, rp_id: &str, user_names: &[String]) -> keylib_ctap::Result<usize> {
        if let Some(select_cb) = &self.callbacks.select {
            select_cb(rp_id, user_names).map_err(|_| StatusCode::Other)
        } else {
            Ok(0) // Default to first credential
        }
    }
}

#[cfg(feature = "pure-rust")]
impl CredentialStorageCallbacks for CallbackAdapter {
    fn write_credential(&self, credential: &CtapCredential) -> keylib_ctap::Result<()> {
        if let Some(write_cb) = &self.callbacks.write {
            // Convert keylib-ctap credential to CredentialRef
            let cred_ref = CredentialRef {
                id: &credential.id,
                rp_id: &credential.rp_id,
                rp_name: credential.rp_name.as_deref(),
                user_id: &credential.user_id,
                user_name: credential.user_name.as_deref(),
                user_display_name: credential.user_display_name.as_deref(),
                sign_count: credential.sign_count,
                alg: credential.algorithm,
                private_key: &credential.private_key,
                created: credential.created,
                discoverable: credential.discoverable,
                cred_protect: Some(credential.cred_protect),
            };
            write_cb(cred_ref).map_err(|_| StatusCode::Other)
        } else {
            Ok(()) // No-op if no callback
        }
    }

    fn delete_credential(&self, credential_id: &[u8]) -> keylib_ctap::Result<()> {
        if let Some(delete_cb) = &self.callbacks.delete {
            delete_cb(credential_id).map_err(|_| StatusCode::Other)
        } else {
            Ok(()) // No-op if no callback
        }
    }

    fn read_credentials(
        &self,
        rp_id: &str,
        user_id: Option<&[u8]>,
    ) -> keylib_ctap::Result<Vec<CtapCredential>> {
        if let Some(read_cb) = &self.callbacks.read_credentials {
            let credentials = read_cb(rp_id, user_id).map_err(|_| StatusCode::NoCredentials)?;
            Ok(credentials.into_iter().map(|c| c.into()).collect())
        } else {
            Ok(vec![]) // Empty list if no callback
        }
    }

    fn credential_exists(&self, credential_id: &[u8]) -> keylib_ctap::Result<bool> {
        if let Some(get_cb) = &self.callbacks.get_credential {
            Ok(get_cb(credential_id).is_ok())
        } else {
            Ok(false)
        }
    }

    fn get_credential(&self, credential_id: &[u8]) -> keylib_ctap::Result<CtapCredential> {
        if let Some(get_cb) = &self.callbacks.get_credential {
            let cred = get_cb(credential_id).map_err(|_| StatusCode::NoCredentials)?;
            Ok(cred.into())
        } else {
            Err(StatusCode::NoCredentials)
        }
    }

    fn update_credential(&self, credential: &CtapCredential) -> keylib_ctap::Result<()> {
        // Update is same as write for our purposes
        self.write_credential(credential)
    }

    fn enumerate_rps(&self) -> keylib_ctap::Result<Vec<(String, Option<String>, usize)>> {
        // Not directly supported in callback model, would need to enumerate all RPs
        Ok(vec![])
    }

    fn credential_count(&self) -> keylib_ctap::Result<usize> {
        // Not directly supported in callback model
        Ok(0)
    }
}

// Note: CallbackAdapter automatically implements AuthenticatorCallbacks
// because there's a blanket impl in keylib-ctap for any type that implements
// both UserInteractionCallbacks and CredentialStorageCallbacks

/// Authenticator configuration (matches zig-ffi)
#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    pub aaguid: [u8; 16],
    pub max_credentials: usize,
    pub extensions: Vec<String>,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            max_credentials: 100,
            extensions: vec![],
        }
    }
}

impl AuthenticatorConfig {
    pub fn builder() -> AuthenticatorConfigBuilder {
        AuthenticatorConfigBuilder::default()
    }
}

/// Builder for AuthenticatorConfig
#[derive(Default)]
pub struct AuthenticatorConfigBuilder {
    aaguid: [u8; 16],
    max_credentials: usize,
    extensions: Vec<String>,
}

impl AuthenticatorConfigBuilder {
    pub fn aaguid(mut self, aaguid: [u8; 16]) -> Self {
        self.aaguid = aaguid;
        self
    }

    pub fn max_credentials(mut self, max: usize) -> Self {
        self.max_credentials = max;
        self
    }

    pub fn extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    pub fn build(self) -> AuthenticatorConfig {
        AuthenticatorConfig {
            aaguid: self.aaguid,
            max_credentials: if self.max_credentials == 0 {
                100
            } else {
                self.max_credentials
            },
            extensions: self.extensions,
        }
    }
}

/// Authenticator wrapper (matches zig-ffi API)
#[cfg(feature = "pure-rust")]
pub struct Authenticator {
    dispatcher: Arc<Mutex<CommandDispatcher<CallbackAdapter>>>,
}

#[cfg(feature = "pure-rust")]
impl Authenticator {
    /// Set the PIN hash for the authenticator (must be called before creating instance)
    ///
    /// Note: In pure-rust, PIN is set per-authenticator instance, not globally.
    /// This is a compatibility shim for zig-ffi API - currently a no-op.
    pub fn set_pin_hash(_pin_hash: &[u8]) {
        // No-op for pure-rust implementation
    }

    /// Create a new authenticator with default configuration
    pub fn new(callbacks: Callbacks) -> Result<Self> {
        Self::with_config(callbacks, AuthenticatorConfig::default())
    }

    /// Create a new authenticator with custom configuration
    pub fn with_config(callbacks: Callbacks, config: AuthenticatorConfig) -> Result<Self> {
        let adapter = CallbackAdapter { callbacks };

        // Create CTAP authenticator config
        let ctap_config = CtapConfig::new()
            .with_aaguid(config.aaguid)
            .with_max_credentials(config.max_credentials)
            .with_extensions(config.extensions);

        let authenticator = CtapAuthenticator::new(ctap_config, adapter);
        let dispatcher = CommandDispatcher::new(authenticator);

        Ok(Self {
            dispatcher: Arc::new(Mutex::new(dispatcher)),
        })
    }

    /// Handle a CTAP request
    ///
    /// # Arguments
    ///
    /// * `request` - CTAP command bytes (command code + CBOR parameters)
    /// * `response` - Buffer for response (will be resized as needed)
    ///
    /// # Returns
    ///
    /// Number of bytes written to response buffer
    pub fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<usize> {
        let mut dispatcher = self.dispatcher.lock().map_err(|_| Error::Other)?;

        // Dispatch command
        match dispatcher.dispatch(request) {
            Ok(response_data) => {
                *response = response_data;
                Ok(response.len())
            }
            Err(status_code) => {
                // Return CTAP error status as single-byte response
                *response = vec![status_code as u8];
                Ok(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_builder() {
        let callbacks = CallbacksBuilder::new()
            .up(Arc::new(|_, _, _| Ok(UpResult::Accepted)))
            .build();

        assert!(callbacks.up.is_some());
        assert!(callbacks.uv.is_none());
    }

    #[test]
    fn test_config_builder() {
        let config = AuthenticatorConfig::builder()
            .aaguid([1u8; 16])
            .max_credentials(50)
            .build();

        assert_eq!(config.aaguid, [1u8; 16]);
        assert_eq!(config.max_credentials, 50);
    }
}
