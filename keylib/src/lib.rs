#![warn(unused_extern_crates)]

pub mod authenticator;
pub mod callbacks;
pub mod client;
pub mod client_pin;
pub mod credential;
pub mod credential_management;
pub mod ctaphid;
pub mod error;
pub mod uhid;

// Re-export the main types for convenience
pub use authenticator::Authenticator;
pub use client::{CborCommand, CborCommandResult, Client, Transport, TransportList};
pub use credential::{Credential, CredentialRef, Meta};
pub use error::{Error, Result};
