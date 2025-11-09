//! Authenticator Options Configuration
//!
//! This module provides fine-grained control over authenticator capabilities
//! and features through the `AuthenticatorOptions` struct.

/// Authenticator options for controlling device capabilities
///
/// These options mirror the CTAP 2.1 authenticator options and allow
/// fine-grained control over what features are advertised and enabled.
///
/// # Tri-State Values
///
/// Some options use a tri-state system:
/// - `Some(true)`: Feature is supported and enabled
/// - `Some(false)`: Feature is supported but disabled
/// - `None`: Feature is not supported
///
/// # Example
///
/// ```rust
/// use keylib::AuthenticatorOptions;
///
/// let opts = AuthenticatorOptions::new()
///     .with_resident_keys(true)
///     .with_user_verification(Some(true))  // UV capable and configured
///     .with_client_pin(Some(true));       // PIN capable and set
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatorOptions {
    /// Resident key (discoverable credentials) support
    pub rk: bool,

    /// User presence capable
    pub up: bool,

    /// User verification: None = not capable, Some(false) = capable but not configured, Some(true) = capable and configured
    pub uv: Option<bool>,

    /// Platform device (cannot be removed)
    pub plat: bool,

    /// Client PIN: None = not capable, Some(false) = capable but not set, Some(true) = capable and set
    pub client_pin: Option<bool>,

    /// PIN/UV auth token support
    pub pin_uv_auth_token: Option<bool>,

    /// Credential management support
    pub cred_mgmt: Option<bool>,

    /// Biometric enrollment support
    pub bio_enroll: Option<bool>,

    /// Large blobs support
    pub large_blobs: Option<bool>,

    /// Enterprise attestation: None = not supported, Some(false) = supported but disabled, Some(true) = supported and enabled
    pub ep: Option<bool>,

    /// Always require user verification
    pub always_uv: Option<bool>,
}

impl Default for AuthenticatorOptions {
    fn default() -> Self {
        Self {
            rk: true,
            up: true,
            uv: None, // Will be determined by callbacks
            plat: false,
            client_pin: Some(true),
            pin_uv_auth_token: Some(true),
            cred_mgmt: None,
            bio_enroll: None,
            large_blobs: None,
            ep: None,
            always_uv: None,
        }
    }
}

impl AuthenticatorOptions {
    /// Create new options with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set resident key (discoverable credentials) support
    pub fn with_resident_keys(mut self, enabled: bool) -> Self {
        self.rk = enabled;
        self
    }

    /// Set user presence capability
    pub fn with_user_presence(mut self, enabled: bool) -> Self {
        self.up = enabled;
        self
    }

    /// Set user verification capability and configuration
    /// - `None`: Not capable of user verification
    /// - `Some(false)`: Capable but not yet configured
    /// - `Some(true)`: Capable and configured
    pub fn with_user_verification(mut self, state: Option<bool>) -> Self {
        self.uv = state;
        self
    }

    /// Set platform device flag (cannot be removed from client)
    pub fn with_platform_device(mut self, is_platform: bool) -> Self {
        self.plat = is_platform;
        self
    }

    /// Set client PIN capability and configuration
    /// - `None`: Not capable of client PIN
    /// - `Some(false)`: Capable but PIN not set
    /// - `Some(true)`: Capable and PIN is set
    pub fn with_client_pin(mut self, state: Option<bool>) -> Self {
        self.client_pin = state;
        self
    }

    /// Set PIN/UV auth token support
    pub fn with_pin_uv_auth_token(mut self, state: Option<bool>) -> Self {
        self.pin_uv_auth_token = state;
        self
    }

    /// Set credential management support (CTAP 2.1)
    pub fn with_credential_management(mut self, state: Option<bool>) -> Self {
        self.cred_mgmt = state;
        self
    }

    /// Set biometric enrollment support
    pub fn with_biometric_enrollment(mut self, state: Option<bool>) -> Self {
        self.bio_enroll = state;
        self
    }

    /// Set large blobs support
    pub fn with_large_blobs(mut self, state: Option<bool>) -> Self {
        self.large_blobs = state;
        self
    }

    /// Set enterprise attestation support
    /// - `None`: Not supported
    /// - `Some(false)`: Supported but disabled
    /// - `Some(true)`: Supported and enabled
    pub fn with_enterprise_attestation(mut self, state: Option<bool>) -> Self {
        self.ep = state;
        self
    }

    /// Set always require user verification
    pub fn with_always_uv(mut self, state: Option<bool>) -> Self {
        self.always_uv = state;
        self
    }
}
