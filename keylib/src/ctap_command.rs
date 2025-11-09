//! CTAP Command Types
//!
//! This module provides a type-safe representation of CTAP 2.1 commands
//! that can be configured for an authenticator.

/// CTAP 2.1 Command Codes
///
/// Represents the standard commands defined in the CTAP specification.
/// Note that not all commands may be implemented or available depending
/// on the authenticator configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CtapCommand {
    /// MakeCredential (0x01) - Create a new credential
    MakeCredential = 0x01,
    /// GetAssertion (0x02) - Generate an authentication assertion
    GetAssertion = 0x02,
    /// GetInfo (0x04) - Get authenticator information
    GetInfo = 0x04,
    /// ClientPIN (0x06) - PIN/UV protocol operations
    ClientPin = 0x06,
    /// Reset (0x07) - Reset the authenticator (not yet implemented)
    Reset = 0x07,
    /// GetNextAssertion (0x08) - Get the next assertion from a batch
    GetNextAssertion = 0x08,
    /// BioEnrollment (0x09) - Biometric enrollment operations (not yet implemented)
    BioEnrollment = 0x09,
    /// CredentialManagement (0x0a) - Manage stored credentials (not yet fully implemented)
    CredentialManagement = 0x0a,
    /// Selection (0x0b) - Authenticator selection
    Selection = 0x0b,
    /// LargeBlobs (0x0c) - Large blob storage operations (not yet implemented)
    LargeBlobs = 0x0c,
    /// Config (0x0d) - Authenticator configuration (not yet implemented)
    Config = 0x0d,
}

impl CtapCommand {
    /// Get the command code as a byte value
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Create a CtapCommand from a byte value
    ///
    /// Returns `None` if the byte doesn't correspond to a valid command.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::MakeCredential),
            0x02 => Some(Self::GetAssertion),
            0x04 => Some(Self::GetInfo),
            0x06 => Some(Self::ClientPin),
            0x07 => Some(Self::Reset),
            0x08 => Some(Self::GetNextAssertion),
            0x09 => Some(Self::BioEnrollment),
            0x0a => Some(Self::CredentialManagement),
            0x0b => Some(Self::Selection),
            0x0c => Some(Self::LargeBlobs),
            0x0d => Some(Self::Config),
            _ => None,
        }
    }

    /// Get the default set of commands for a basic authenticator
    ///
    /// Returns the minimal set of commands typically supported:
    /// - MakeCredential
    /// - GetAssertion
    /// - GetInfo
    /// - ClientPin
    /// - Selection
    pub fn default_commands() -> Vec<Self> {
        vec![
            Self::MakeCredential,
            Self::GetAssertion,
            Self::GetInfo,
            Self::ClientPin,
            Self::Selection,
        ]
    }
}

impl From<CtapCommand> for u8 {
    fn from(cmd: CtapCommand) -> Self {
        cmd.as_u8()
    }
}

impl std::fmt::Display for CtapCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MakeCredential => write!(f, "MakeCredential(0x01)"),
            Self::GetAssertion => write!(f, "GetAssertion(0x02)"),
            Self::GetInfo => write!(f, "GetInfo(0x04)"),
            Self::ClientPin => write!(f, "ClientPin(0x06)"),
            Self::Reset => write!(f, "Reset(0x07)"),
            Self::GetNextAssertion => write!(f, "GetNextAssertion(0x08)"),
            Self::BioEnrollment => write!(f, "BioEnrollment(0x09)"),
            Self::CredentialManagement => write!(f, "CredentialManagement(0x0a)"),
            Self::Selection => write!(f, "Selection(0x0b)"),
            Self::LargeBlobs => write!(f, "LargeBlobs(0x0c)"),
            Self::Config => write!(f, "Config(0x0d)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_codes() {
        assert_eq!(CtapCommand::MakeCredential.as_u8(), 0x01);
        assert_eq!(CtapCommand::GetAssertion.as_u8(), 0x02);
        assert_eq!(CtapCommand::GetInfo.as_u8(), 0x04);
    }

    #[test]
    fn test_from_u8() {
        assert_eq!(
            CtapCommand::from_u8(0x01),
            Some(CtapCommand::MakeCredential)
        );
        assert_eq!(CtapCommand::from_u8(0x02), Some(CtapCommand::GetAssertion));
        assert_eq!(CtapCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_default_commands() {
        let defaults = CtapCommand::default_commands();
        assert_eq!(defaults.len(), 5);
        assert!(defaults.contains(&CtapCommand::MakeCredential));
        assert!(defaults.contains(&CtapCommand::GetAssertion));
    }
}
