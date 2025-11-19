#![warn(unused_extern_crates)]

// Common types
pub mod common;

// Pure Rust CTAP implementation
pub mod rust_impl;

// Re-export main types at root level for convenience
pub use rust_impl::authenticator::{
    Authenticator, AuthenticatorConfig, AuthenticatorConfigBuilder, Callbacks, CallbacksBuilder,
    DeleteCallback, ReadCallback, ReadFirstCallback, ReadNextCallback, SelectCallback, UpCallback,
    UpResult, UvCallback, UvResult, WriteCallback,
};
pub use rust_impl::authenticator_options::AuthenticatorOptions;
pub use rust_impl::client::Client;
pub use rust_impl::client_pin::PinProtocol;
pub use rust_impl::ctap_command::CtapCommand;
pub use rust_impl::transport::{Transport, TransportList};
#[cfg(target_os = "linux")]
pub use rust_impl::uhid::Uhid;

// Re-export common types
pub use common::{
    ClientDataHash, Credential, CredentialRef, Error, Extensions, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol, RelyingParty, Result, User,
};
