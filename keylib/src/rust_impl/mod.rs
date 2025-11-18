//! Pure Rust CTAP Implementation
//!
//! This module provides access to the pure Rust CTAP implementation,
//! available when the "pure-rust" feature is enabled.

#[cfg(feature = "pure-rust")]
pub mod authenticator;
#[cfg(feature = "pure-rust")]
pub mod authenticator_options;
#[cfg(feature = "pure-rust")]
pub mod ctap_command;
#[cfg(feature = "pure-rust")]
pub mod client;
#[cfg(feature = "pure-rust")]
pub mod client_pin;
#[cfg(feature = "pure-rust")]
pub mod transport;
#[cfg(all(feature = "pure-rust", target_os = "linux"))]
pub mod uhid;

// Re-export core types from pure Rust crates
#[cfg(feature = "pure-rust")]
pub use keylib_crypto;
#[cfg(feature = "pure-rust")]
pub use keylib_ctap;
#[cfg(feature = "pure-rust")]
pub use keylib_transport;
