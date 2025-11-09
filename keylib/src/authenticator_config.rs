//! Configuration types for the FIDO2 authenticator
//!
//! This module provides types for configuring authenticator behavior, including
//! AAGUID, supported commands, options, and extensions.

use crate::authenticator_options::AuthenticatorOptions;
use crate::ctap_command::CtapCommand;

/// Authenticator configuration
///
/// This struct allows you to configure various aspects of the authenticator
/// including its AAGUID, which CTAP commands are enabled, options, extensions,
/// and credential limits.
///
/// # Example
///
/// ```no_run
/// use keylib::{AuthenticatorConfig, CtapCommand, AuthenticatorOptions};
///
/// let config = AuthenticatorConfig::builder()
///     .aaguid([0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d,
///              0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29, 0x7c, 0x88])
///     .commands(vec![
///         CtapCommand::MakeCredential,
///         CtapCommand::GetAssertion,
///         CtapCommand::GetInfo,
///     ])
///     .options(AuthenticatorOptions::new()
///         .with_resident_keys(true)
///         .with_user_verification(Some(true)))
///     .max_credentials(50)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatorConfig {
    /// AAGUID (Authenticator Attestation GUID) - 16 bytes identifying the authenticator model
    pub aaguid: [u8; 16],

    /// List of CTAP commands to enable
    pub commands: Vec<CtapCommand>,

    /// Authenticator options controlling capabilities
    pub options: Option<AuthenticatorOptions>,

    /// Maximum number of discoverable credentials (resident keys)
    pub max_credentials: Option<u32>,

    /// List of supported extensions
    pub extensions: Option<Vec<String>>,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            // Default AAGUID from keylib
            aaguid: [
                0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
                0x7c, 0x88,
            ],
            commands: CtapCommand::default_commands(),
            options: None,         // Use Zig defaults
            max_credentials: None, // Use Zig default (25)
            extensions: None,      // Use Zig defaults
        }
    }
}

impl AuthenticatorConfig {
    /// Create a new builder for constructing configuration
    pub fn builder() -> AuthenticatorConfigBuilder {
        AuthenticatorConfigBuilder::new()
    }
}

/// Builder for constructing authenticator configuration
#[derive(Debug)]
pub struct AuthenticatorConfigBuilder {
    config: AuthenticatorConfig,
}

impl AuthenticatorConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            config: AuthenticatorConfig::default(),
        }
    }

    /// Set the AAGUID (Authenticator Attestation GUID)
    ///
    /// # Arguments
    /// * `aaguid` - 16-byte array identifying the authenticator model
    pub fn aaguid(mut self, aaguid: [u8; 16]) -> Self {
        self.config.aaguid = aaguid;
        self
    }

    /// Set the list of enabled CTAP commands
    ///
    /// # Arguments
    /// * `commands` - Vector of CTAP commands to enable
    pub fn commands(mut self, commands: Vec<CtapCommand>) -> Self {
        self.config.commands = commands;
        self
    }

    /// Set authenticator options
    ///
    /// # Arguments
    /// * `options` - Authenticator options controlling capabilities
    pub fn options(mut self, options: AuthenticatorOptions) -> Self {
        self.config.options = Some(options);
        self
    }

    /// Set maximum number of discoverable credentials
    ///
    /// # Arguments
    /// * `max` - Maximum resident keys to allow (default: 25)
    pub fn max_credentials(mut self, max: u32) -> Self {
        self.config.max_credentials = Some(max);
        self
    }

    /// Set supported extensions
    ///
    /// # Arguments
    /// * `extensions` - List of extension identifiers (e.g., "credProtect", "hmac-secret")
    pub fn extensions(mut self, extensions: Vec<String>) -> Self {
        self.config.extensions = Some(extensions);
        self
    }

    /// Build the final configuration
    pub fn build(self) -> AuthenticatorConfig {
        self.config
    }
}

impl Default for AuthenticatorConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
