//! Error types for cryptographic operations

use thiserror::Error;

/// Cryptographic operation errors
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid public key provided
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid private key provided
    #[error("Invalid private key")]
    InvalidPrivateKey,

    /// Invalid signature format
    #[error("Invalid signature")]
    InvalidSignature,

    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// ECDH key agreement failed
    #[error("ECDH key agreement failed")]
    KeyAgreementFailed,

    /// Invalid COSE key format
    #[error("Invalid COSE key format")]
    InvalidCoseKey,
}

/// Result type alias for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;
