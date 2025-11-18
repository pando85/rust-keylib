//! Common types and traits shared between zig-ffi and pure-rust implementations
//!
//! This module provides a unified interface that allows the same test code
//! to work with both the zig-ffi and pure-rust backends.

pub mod client;
pub mod credential;
pub mod error;

// Re-export commonly used types
pub use client::{
    ClientDataHash, CredentialDescriptor, CredentialType, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
};
pub use credential::{Credential, CredentialRef, Extensions, RelyingParty, User};
pub use error::{Error, Result};
