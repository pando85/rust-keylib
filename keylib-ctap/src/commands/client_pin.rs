//! authenticatorClientPIN command
//!
//! Handles PIN management operations including:
//! - Getting PIN retry counter
//! - Getting key agreement
//! - Setting PIN
//! - Changing PIN
//! - Getting PIN token
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN>

use crate::authenticator::Authenticator;
use crate::callbacks::AuthenticatorCallbacks;
use crate::cbor::{MapBuilder, MapParser};
use crate::status::{Result, StatusCode};

/// ClientPIN subcommand codes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum SubCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

/// Request keys
mod req_keys {
    pub const PIN_UV_AUTH_PROTOCOL: i32 = 0x01;
    pub const SUBCOMMAND: i32 = 0x02;
    pub const KEY_AGREEMENT: i32 = 0x03;
    pub const PIN_UV_AUTH_PARAM: i32 = 0x04;
    pub const NEW_PIN_ENC: i32 = 0x05;
    pub const PIN_HASH_ENC: i32 = 0x06;
    pub const PERMISSIONS: i32 = 0x09;
    pub const RP_ID: i32 = 0x0A;
}

/// Response keys
mod resp_keys {
    pub const KEY_AGREEMENT: i32 = 0x01;
    pub const PIN_UV_AUTH_TOKEN: i32 = 0x02;
    pub const PIN_RETRIES: i32 = 0x03;
    pub const POWER_CYCLE_STATE: i32 = 0x04;
    pub const UV_RETRIES: i32 = 0x05;
}

/// Handle authenticatorClientPIN command
///
/// This is a simplified implementation that supports basic PIN operations.
pub fn handle<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let parser = MapParser::from_bytes(data)?;

    let subcommand: u8 = parser.get(req_keys::SUBCOMMAND)?;

    match subcommand {
        0x01 => handle_get_pin_retries(auth),
        0x02 => handle_get_key_agreement(auth, &parser),
        0x03 => handle_set_pin(auth, &parser),
        0x04 => handle_change_pin(auth, &parser),
        0x05 => handle_get_pin_token(auth, &parser),
        _ => Err(StatusCode::InvalidSubcommand),
    }
}

/// Handle getPinRetries subcommand
fn handle_get_pin_retries<C: AuthenticatorCallbacks>(auth: &Authenticator<C>) -> Result<Vec<u8>> {
    MapBuilder::new()
        .insert(resp_keys::PIN_RETRIES, auth.pin_retries() as i32)?
        .build()
}

/// Handle getKeyAgreement subcommand
fn handle_get_key_agreement<C: AuthenticatorCallbacks>(
    _auth: &Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    let _protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;

    // Generate ephemeral ECDH key pair
    let keypair = keylib_crypto::ecdh::KeyPair::generate()?;
    let (x, y) = keypair.public_key_cose();

    // Build COSE key
    let key_agreement = MapBuilder::new()
        .insert(1, 2)? // kty: EC2
        .insert(3, -25)? // alg: ECDH-ES + HKDF-256
        .insert(-1, 1)? // crv: P-256
        .insert(-2, x.as_slice())? // x coordinate
        .insert(-3, y.as_slice())? // y coordinate
        .build_value();

    MapBuilder::new()
        .insert(resp_keys::KEY_AGREEMENT, key_agreement)?
        .build()
}

/// Handle setPin subcommand (simplified)
fn handle_set_pin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if auth.is_pin_set() {
        return Err(StatusCode::PinAuthInvalid);
    }

    let _protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let _new_pin_enc: Vec<u8> = parser.get(req_keys::NEW_PIN_ENC)?;
    let _pin_uv_auth_param: Vec<u8> = parser.get(req_keys::PIN_UV_AUTH_PARAM)?;

    // TODO: Decrypt PIN, validate, and set
    // For now, just set a dummy PIN
    auth.set_pin("1234")?;

    MapBuilder::new().build()
}

/// Handle changePin subcommand (simplified)
fn handle_change_pin<C: AuthenticatorCallbacks>(
    auth: &mut Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if !auth.is_pin_set() {
        return Err(StatusCode::PinNotSet);
    }

    let _protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let _pin_hash_enc: Vec<u8> = parser.get(req_keys::PIN_HASH_ENC)?;
    let _new_pin_enc: Vec<u8> = parser.get(req_keys::NEW_PIN_ENC)?;
    let _pin_uv_auth_param: Vec<u8> = parser.get(req_keys::PIN_UV_AUTH_PARAM)?;

    // TODO: Verify old PIN, decrypt new PIN, validate, and set
    // For now, just accept the change
    auth.change_pin("1234", "5678")?;

    MapBuilder::new().build()
}

/// Handle getPinToken subcommand (simplified)
fn handle_get_pin_token<C: AuthenticatorCallbacks>(
    auth: &Authenticator<C>,
    parser: &MapParser,
) -> Result<Vec<u8>> {
    if !auth.is_pin_set() {
        return Err(StatusCode::PinNotSet);
    }

    let _protocol: u8 = parser.get(req_keys::PIN_UV_AUTH_PROTOCOL)?;
    let _pin_hash_enc: Vec<u8> = parser.get(req_keys::PIN_HASH_ENC)?;

    // TODO: Verify PIN, generate token
    // For now, return a dummy encrypted token
    let dummy_token = vec![0u8; 32];

    MapBuilder::new()
        .insert(resp_keys::PIN_UV_AUTH_TOKEN, dummy_token)?
        .build()
}
