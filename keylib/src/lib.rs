#![warn(unused_extern_crates)]

mod authenticator;
mod authenticator_config;
mod authenticator_options;
mod callbacks;
pub mod client;
pub mod client_pin;
pub mod credential;
pub mod credential_management;
pub mod ctap_command;
pub mod ctaphid;
mod custom_command;
pub mod error;
pub mod uhid;

// Re-export the main types for convenience
pub use authenticator::Authenticator;
pub use authenticator_config::{AuthenticatorConfig, AuthenticatorConfigBuilder};
pub use authenticator_options::AuthenticatorOptions;
pub use callbacks::{
    Callbacks, CallbacksBuilder, DeleteCallback, ReadCallback, UpCallback, UpResult, UvCallback,
    UvResult, WriteCallback,
};
pub use client::{CborCommand, CborCommandResult, Client, Transport, TransportList};
pub use credential::{Credential, CredentialRef, Meta};
pub use ctap_command::CtapCommand;
pub use custom_command::{CustomCommand, CustomCommandHandler};
pub use error::{Error, Result};
