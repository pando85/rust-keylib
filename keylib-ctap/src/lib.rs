//! Pure Rust CTAP (Client to Authenticator Protocol) implementation
//!
//! This crate provides the CTAP 2.0/2.1 protocol logic for FIDO2 authenticators.
//!
//! Implements the FIDO2 specification:
//! <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html>

pub mod authenticator;
pub mod callbacks;
pub mod cbor;
pub mod commands;
pub mod extensions;
pub mod pin_token;
pub mod status;
pub mod types;

// Re-export commonly used types
pub use authenticator::{Authenticator, AuthenticatorConfig};
pub use callbacks::{
    AuthenticatorCallbacks, CredentialStorageCallbacks, UpResult, UserInteractionCallbacks,
    UvResult,
};
pub use pin_token::{Permission, PinToken, PinTokenManager};
pub use status::{Result, StatusCode};
pub use types::{
    CoseAlgorithm, CredProtect, Credential, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, RelyingParty, User,
};
