//! Pure Rust CTAP Implementation
//!
//! This module provides access to the pure Rust CTAP implementation,
//! available when the "pure-rust" feature is enabled.

#[cfg(feature = "pure-rust")]
pub mod authenticator;
#[cfg(feature = "pure-rust")]
pub mod transport;

// Re-export core types from pure Rust crates
#[cfg(feature = "pure-rust")]
pub use keylib_crypto;
#[cfg(feature = "pure-rust")]
pub use keylib_ctap;
#[cfg(feature = "pure-rust")]
pub use keylib_transport;
