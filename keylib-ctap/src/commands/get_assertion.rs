//! authenticatorGetAssertion command
//!
//! Authenticates a user with an existing credential.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::status::{Result, StatusCode};

/// Handle authenticatorGetAssertion command
///
/// This is a placeholder implementation. Full implementation coming in next phase.
pub fn handle<C: AuthenticatorCallbacks>(_auth: &mut Authenticator<C>, _data: &[u8]) -> Result<Vec<u8>> {
    // TODO: Implement full GetAssertion command
    Err(StatusCode::InvalidCommand)
}
