//! Pure Rust Authenticator Implementation
//!
//! Provides a high-level interface matching the zig-ffi Authenticator API.

use crate::common::{Credential, CredentialRef, Error, Result};

#[cfg(feature = "pure-rust")]
use keylib_ctap::{
    CommandDispatcher, StatusCode,
    authenticator::{Authenticator as CtapAuthenticator, AuthenticatorConfig as CtapConfig},
    callbacks::{
        CredentialStorageCallbacks, UpResult as CtapUpResult, UserInteractionCallbacks,
        UvResult as CtapUvResult,
    },
    types::Credential as CtapCredential,
};

#[cfg(feature = "pure-rust")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "pure-rust")]
use std::sync::OnceLock;

/// Global PIN hash storage for zig-ffi API compatibility
/// This allows set_pin_hash to be called before creating an authenticator
#[cfg(feature = "pure-rust")]
static PRESET_PIN_HASH: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();

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

/// Select callback type for choosing which user to authenticate with (zig-ffi compatible)
pub type SelectCallback = Arc<dyn Fn(&str) -> Result<Vec<String>> + Send + Sync>;

/// Read callback type for retrieving credential data (zig-ffi compatible)
pub type ReadCallback = Arc<dyn Fn(&str, &str) -> Result<Vec<u8>> + Send + Sync>;

/// Write callback type for storing credential data (zig-ffi compatible)
pub type WriteCallback = Arc<dyn Fn(&str, &str, CredentialRef) -> Result<()> + Send + Sync>;

/// Delete callback type for removing credential data (zig-ffi compatible)
pub type DeleteCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Read first callback type for starting credential iteration (zig-ffi compatible)
pub type ReadFirstCallback =
    Arc<dyn Fn(Option<&str>, Option<&str>, Option<[u8; 32]>) -> Result<Credential> + Send + Sync>;

/// Read next callback type for continuing credential iteration (zig-ffi compatible)
pub type ReadNextCallback = Arc<dyn Fn() -> Result<Credential> + Send + Sync>;

/// Read credentials callback type (pure-rust legacy, kept for backward compatibility)
pub type ReadCredentialsCallback =
    Arc<dyn Fn(&str, Option<&[u8]>) -> Result<Vec<Credential>> + Send + Sync>;

/// Get credential callback type (pure-rust legacy, kept for backward compatibility)
pub type GetCredentialCallback = Arc<dyn Fn(&[u8]) -> Result<Credential> + Send + Sync>;

/// Callback wrapper (matches zig-ffi Callbacks API)
#[derive(Clone, Default)]
pub struct Callbacks {
    pub up: Option<UpCallback>,
    pub uv: Option<UvCallback>,
    pub select: Option<SelectCallback>,
    pub read: Option<ReadCallback>,
    pub write: Option<WriteCallback>,
    pub delete: Option<DeleteCallback>,
    pub read_first: Option<ReadFirstCallback>,
    pub read_next: Option<ReadNextCallback>,
    // Legacy pure-rust callbacks (kept for backward compatibility)
    pub read_credentials: Option<ReadCredentialsCallback>,
    pub get_credential: Option<GetCredentialCallback>,
}

/// Builder for creating Callbacks instances
#[derive(Default)]
pub struct CallbacksBuilder {
    up: Option<UpCallback>,
    uv: Option<UvCallback>,
    select: Option<SelectCallback>,
    read: Option<ReadCallback>,
    write: Option<WriteCallback>,
    delete: Option<DeleteCallback>,
    read_first: Option<ReadFirstCallback>,
    read_next: Option<ReadNextCallback>,
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

    pub fn read(mut self, callback: ReadCallback) -> Self {
        self.read = Some(callback);
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

    pub fn read_first(mut self, callback: ReadFirstCallback) -> Self {
        self.read_first = Some(callback);
        self
    }

    pub fn read_next(mut self, callback: ReadNextCallback) -> Self {
        self.read_next = Some(callback);
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
            read: self.read,
            write: self.write,
            delete: self.delete,
            read_first: self.read_first,
            read_next: self.read_next,
            read_credentials: self.read_credentials,
            get_credential: self.get_credential,
        }
    }
}

impl Callbacks {
    /// Create a new Callbacks instance (zig-ffi compatible constructor)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        up: Option<UpCallback>,
        uv: Option<UvCallback>,
        select: Option<SelectCallback>,
        read: Option<ReadCallback>,
        write: Option<WriteCallback>,
        delete: Option<DeleteCallback>,
        read_first: Option<ReadFirstCallback>,
        read_next: Option<ReadNextCallback>,
    ) -> Self {
        Self {
            up,
            uv,
            select,
            read,
            write,
            delete,
            read_first,
            read_next,
            read_credentials: None,
            get_credential: None,
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

    fn select_credential(&self, rp_id: &str, _user_names: &[String]) -> keylib_ctap::Result<usize> {
        if let Some(select_cb) = &self.callbacks.select {
            // Call zig-ffi compatible select callback which returns the list of users
            // For pure-rust, we ignore the returned user list and just return 0
            select_cb(rp_id).map(|_| 0).map_err(|_| StatusCode::Other)
        } else {
            Ok(0) // Default to first credential
        }
    }
}

#[cfg(feature = "pure-rust")]
impl CredentialStorageCallbacks for CallbackAdapter {
    fn write_credential(&self, credential: &CtapCredential) -> keylib_ctap::Result<()> {
        if let Some(write_cb) = &self.callbacks.write {
            // Convert credential id to string for zig-ffi compatible signature
            let id_str = std::str::from_utf8(&credential.id).unwrap_or_else(|_| {
                std::str::from_utf8(&credential.id[..credential.id.len().min(16)]).unwrap_or("")
            });

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
            // Call zig-ffi compatible write callback: (id, rp_id, credential_ref)
            write_cb(id_str, &credential.rp_id, cred_ref).map_err(|_| StatusCode::Other)
        } else {
            Ok(()) // No-op if no callback
        }
    }

    fn delete_credential(&self, credential_id: &[u8]) -> keylib_ctap::Result<()> {
        if let Some(delete_cb) = &self.callbacks.delete {
            // Convert credential id to string for zig-ffi compatible signature
            let id_str = std::str::from_utf8(credential_id).unwrap_or_else(|_| {
                std::str::from_utf8(&credential_id[..credential_id.len().min(16)]).unwrap_or("")
            });
            delete_cb(id_str).map_err(|_| StatusCode::Other)
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
    pub commands: Vec<super::ctap_command::CtapCommand>,
    pub options: Option<super::authenticator_options::AuthenticatorOptions>,
    pub max_credentials: usize,
    pub extensions: Vec<String>,
    pub force_resident_keys: bool,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            commands: super::ctap_command::CtapCommand::default_commands(),
            options: None,
            max_credentials: 100,
            extensions: vec![],
            force_resident_keys: false,
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
    commands: Vec<super::ctap_command::CtapCommand>,
    options: Option<super::authenticator_options::AuthenticatorOptions>,
    max_credentials: usize,
    extensions: Vec<String>,
    force_resident_keys: bool,
}

impl AuthenticatorConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn aaguid(mut self, aaguid: [u8; 16]) -> Self {
        self.aaguid = aaguid;
        self
    }

    pub fn commands(mut self, commands: Vec<super::ctap_command::CtapCommand>) -> Self {
        self.commands = commands;
        self
    }

    pub fn options(mut self, options: super::authenticator_options::AuthenticatorOptions) -> Self {
        self.options = Some(options);
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

    pub fn force_resident_keys(mut self, force: bool) -> Self {
        self.force_resident_keys = force;
        self
    }

    pub fn build(self) -> AuthenticatorConfig {
        AuthenticatorConfig {
            aaguid: self.aaguid,
            commands: if self.commands.is_empty() {
                super::ctap_command::CtapCommand::default_commands()
            } else {
                self.commands
            },
            options: self.options,
            max_credentials: if self.max_credentials == 0 {
                100
            } else {
                self.max_credentials
            },
            extensions: self.extensions,
            force_resident_keys: self.force_resident_keys,
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
    /// This is a compatibility method for zig-ffi API. The PIN hash will be applied
    /// to the next authenticator instance created.
    ///
    /// # Arguments
    ///
    /// * `pin_hash` - SHA-256 hash of the PIN (32 bytes)
    pub fn set_pin_hash(pin_hash: &[u8]) {
        if pin_hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(pin_hash);

            let lock = PRESET_PIN_HASH.get_or_init(|| Mutex::new(None));
            if let Ok(mut guard) = lock.lock() {
                *guard = Some(hash);
            }
        }
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
            .with_extensions(config.extensions)
            .with_force_resident_keys(config.force_resident_keys);

        let mut authenticator = CtapAuthenticator::new(ctap_config, adapter);

        // Apply preset PIN hash if available (for zig-ffi API compatibility)
        if let Some(lock) = PRESET_PIN_HASH.get() {
            if let Ok(mut guard) = lock.lock() {
                if let Some(pin_hash) = guard.take() {
                    // Set the PIN hash directly on the authenticator
                    // We use the internal method that sets the hash without validation
                    authenticator.set_pin_hash_for_testing(pin_hash);
                }
            }
        }

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
                // CTAP success response: [0x00 status] [CBOR data...]
                response.clear();
                response.push(0x00); // Success status byte
                response.extend_from_slice(&response_data);
                Ok(response.len())
            }
            Err(status_code) => {
                // CTAP error response: [error status byte] (no CBOR data)
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
