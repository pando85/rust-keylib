#![warn(unused_extern_crates)]

// Common types shared between implementations (always available)
pub mod common;

// Zig FFI modules (legacy, available with "zig-ffi" feature - enabled by default)
#[cfg(feature = "zig-ffi")]
mod authenticator;
#[cfg(feature = "zig-ffi")]
mod authenticator_config;
#[cfg(feature = "zig-ffi")]
mod authenticator_options;
#[cfg(feature = "zig-ffi")]
mod callbacks;
#[cfg(feature = "zig-ffi")]
pub mod client;
#[cfg(feature = "zig-ffi")]
pub mod client_pin;
#[cfg(feature = "zig-ffi")]
pub mod credential;
#[cfg(feature = "zig-ffi")]
pub mod credential_management;
#[cfg(feature = "zig-ffi")]
pub mod ctap_command;
#[cfg(feature = "zig-ffi")]
pub mod ctaphid;
#[cfg(feature = "zig-ffi")]
mod custom_command;
#[cfg(feature = "zig-ffi")]
pub mod error;
#[cfg(feature = "zig-ffi")]
pub mod uhid;

// Pure Rust implementation (available with "pure-rust" feature)
#[cfg(feature = "pure-rust")]
pub mod rust_impl;

// Re-export the main types for convenience (Zig FFI version)
#[cfg(feature = "zig-ffi")]
pub use authenticator::Authenticator;
#[cfg(feature = "zig-ffi")]
pub use authenticator_config::{AuthenticatorConfig, AuthenticatorConfigBuilder};
#[cfg(feature = "zig-ffi")]
pub use authenticator_options::AuthenticatorOptions;
#[cfg(feature = "zig-ffi")]
pub use callbacks::{
    Callbacks, CallbacksBuilder, DeleteCallback, ReadCallback, ReadFirstCallback, ReadNextCallback,
    SelectCallback, UpCallback, UpResult, UvCallback, UvResult, WriteCallback,
};
#[cfg(feature = "zig-ffi")]
pub use client::{CborCommand, CborCommandResult, Client, Transport, TransportList};
#[cfg(feature = "zig-ffi")]
pub use credential::{Credential, CredentialRef, Meta};
#[cfg(feature = "zig-ffi")]
pub use ctap_command::CtapCommand;
#[cfg(feature = "zig-ffi")]
pub use custom_command::{CustomCommand, CustomCommandHandler};
#[cfg(feature = "zig-ffi")]
pub use error::{Error, Result};

// Re-export pure-rust types at root level when pure-rust is active (without zig-ffi)
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::authenticator::{
    Authenticator, AuthenticatorConfig, AuthenticatorConfigBuilder, Callbacks, CallbacksBuilder,
    DeleteCallback, ReadCallback, ReadFirstCallback, ReadNextCallback, SelectCallback, UpCallback,
    UpResult, UvCallback, UvResult, WriteCallback,
};
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::authenticator_options::AuthenticatorOptions;
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::client::Client;
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::client_pin::PinProtocol;
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::ctap_command::CtapCommand;
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
pub use rust_impl::transport::{Transport, TransportList};
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi"), target_os = "linux"))]
pub use rust_impl::uhid::Uhid;

// Re-export common types (always available)
pub use common::{
    ClientDataHash, Credential, CredentialRef, Error, GetAssertionRequest, MakeCredentialRequest,
    PinUvAuth, PinUvAuthProtocol, RelyingParty, Result, User,
};
