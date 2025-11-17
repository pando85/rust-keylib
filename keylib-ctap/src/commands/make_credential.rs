//! authenticatorMakeCredential command
//!
//! Creates a new credential for a relying party.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::status::{Result, StatusCode};

/// Handle authenticatorMakeCredential command
///
/// This is a placeholder implementation. Full implementation coming in next phase.
pub fn handle<C: AuthenticatorCallbacks>(_auth: &mut Authenticator<C>, _data: &[u8]) -> Result<Vec<u8>> {
    // TODO: Implement full MakeCredential command
    Err(StatusCode::InvalidCommand)
}
