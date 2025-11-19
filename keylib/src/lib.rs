#![warn(unused_extern_crates)]

//! # keylib
//!
//! A pure Rust FIDO2/WebAuthn CTAP2 implementation providing virtual authenticator
//! capabilities for testing and development.
//!
//! ## Architecture
//!
//! - **Authenticator**: Virtual FIDO2 authenticator with callback-based user interaction
//! - **Client**: High-level API for communicating with authenticators
//! - **Transport**: USB HID and Linux UHID transport layers
//! - **PIN Protocol**: CTAP2 PIN/UV authentication
//!
//! ## Example
//!
//! ```no_run
//! use keylib::{TransportList, Client};
//!
//! let mut list = TransportList::enumerate()?;
//! let mut transport = list.get(0).unwrap();
//! transport.open()?;
//!
//! let info = Client::authenticator_get_info(&mut transport)?;
//! # Ok::<(), keylib::Error>(())
//! ```

// Core modules
pub mod authenticator;
pub mod client;
pub mod ctap;
pub mod error;
pub mod options;
pub mod pin;
pub mod request;
pub mod transport;
pub mod types;

#[cfg(target_os = "linux")]
pub mod uhid;

// Re-export main types at root level for convenience
pub use authenticator::{
    Authenticator, AuthenticatorConfig, AuthenticatorConfigBuilder, Callbacks, CallbacksBuilder,
    DeleteCallback, ReadCallback, ReadFirstCallback, ReadNextCallback, SelectCallback, UpCallback,
    UpResult, UvCallback, UvResult, WriteCallback,
};
pub use client::Client;
pub use ctap::CtapCommand;
pub use error::{Error, Result};
pub use options::AuthenticatorOptions;
pub use pin::{PinProtocol, PinUvAuthEncapsulation};
pub use request::{
    ClientDataHash, CredentialDescriptor, CredentialType, GetAssertionRequest,
    MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
};
pub use transport::{Transport, TransportList};
pub use types::{Credential, CredentialRef, Extensions, RelyingParty, User};

#[cfg(target_os = "linux")]
pub use uhid::Uhid;
