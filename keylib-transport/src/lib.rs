//! Pure Rust CTAP Transport Layer
//!
//! This crate provides transport implementations for CTAP (Client to Authenticator Protocol):
//! - CTAP HID protocol (message framing, fragmentation, reassembly)
//! - USB HID transport (via hidapi)
//! - Linux UHID virtual device support (for testing)
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#usb>

pub mod ctaphid;
pub mod error;

// Re-export commonly used types
pub use ctaphid::{Cmd, Message, Packet};
pub use error::{Error, Result};
