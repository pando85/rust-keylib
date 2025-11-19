//! In-Memory WebAuthn Flow Example (No USB Required)
//!
//! This example demonstrates a complete WebAuthn flow using an in-memory authenticator.
//! Unlike the webauthn_flow example, this doesn't require any hardware or USB support.
//!
//! # Usage
//! ```bash
//! cargo run --example webauthn_inmemory --no-default-features
//! ```

use base64::Engine;
use keylib::common::{Credential, Result};
use keylib::rust_impl::authenticator::{
    Authenticator, AuthenticatorConfig, CallbacksBuilder, UpResult, UvResult,
};
use keylib::rust_impl::authenticator_options::AuthenticatorOptions;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const PIN: &str = "123456";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║   In-Memory WebAuthn Flow (No USB Required)   ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Setup credential storage
    let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));

    // Setup callbacks
    let creds_write = credentials.clone();
    let creds_read = credentials.clone();
    let creds_get = credentials.clone();
    let creds_delete = credentials.clone();

    let callbacks = CallbacksBuilder::new()
        .up(Arc::new(|info, user, rp| {
            println!("[Auth] User presence: {} (user: {:?}, rp: {:?})", info, user, rp);
            Ok(UpResult::Accepted)
        }))
        .uv(Arc::new(|info, user, rp| {
            println!("[Auth] User verification: {} (user: {:?}, rp: {:?})", info, user, rp);
            Ok(UvResult::Accepted)
        }))
        .write(Arc::new(move |rp_id, user_name, cred| {
            let mut store = creds_write.lock().unwrap();
            store.insert(cred.id.to_vec(), cred.to_owned());
            println!("[Auth] Stored credential for {} ({})", user_name, rp_id);
            Ok(())
        }))
        .read_credentials(Arc::new(move |rp_id, _user_id| {
            let store = creds_read.lock().unwrap();
            let filtered: Vec<Credential> = store
                .values()
                .filter(|c| c.rp.id == rp_id)
                .cloned()
                .collect();
            println!("[Auth] Found {} credentials for {}", filtered.len(), rp_id);
            Ok(filtered)
        }))
        .get_credential(Arc::new(move |cred_id| {
            let store = creds_get.lock().unwrap();
            store
                .get(cred_id)
                .cloned()
                .ok_or(keylib::common::Error::DoesNotExist)
        }))
        .delete(Arc::new(move |cred_id| {
            let mut store = creds_delete.lock().unwrap();
            store.remove(cred_id.as_bytes());
            Ok(())
        }))
        .build();

    // Configure authenticator
    println!("[Setup] Creating in-memory authenticator...");
    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true))
                .with_client_pin(Some(true)),
        )
        .build();

    // Set PIN
    let pin_hash = compute_pin_hash(PIN);
    Authenticator::set_pin_hash(&pin_hash);
    println!("[Setup] ✓ Authenticator configured with PIN\n");

    let mut auth = Authenticator::with_config(callbacks, config)?;

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    println!("📱 [1/2] REGISTRATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    println!("[1.1] Preparing makeCredential request...");
    let challenge = b"random-registration-challenge-12345";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.create");

    // Build makeCredential request (CBOR format)
    let make_cred_request = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Example Corporation",
        &[1, 2, 3, 4],  // user ID
        "alice@example.com",
        "Alice",
    );

    println!("[1.2] Calling authenticatorMakeCredential...");

    // Prepare CTAP command: command byte (0x01) + CBOR parameters
    let mut ctap_request = vec![0x01]; // makeCredential command
    ctap_request.extend_from_slice(&make_cred_request);

    // Call authenticator with the full CTAP request
    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    // Parse response - first byte is status, rest is CBOR
    if response.is_empty() {
        eprintln!("❌ Empty response from makeCredential");
        return Err(keylib::common::Error::Other);
    }

    let status = response[0];
    if status != 0x00 {
        eprintln!("❌ makeCredential failed with status: 0x{:02x}", status);
        return Err(keylib::common::Error::Other);
    }

    println!("      ✓ Credential created successfully\n");

    // ============================================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ============================================================
    println!("🔐 [2/2] AUTHENTICATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    println!("[2.1] Preparing getAssertion request...");
    let challenge = b"random-authentication-challenge-67890";
    let client_data_hash = compute_client_data_hash(challenge, ORIGIN, "webauthn.get");

    // Build getAssertion request (CBOR format)
    let get_assertion_request = build_get_assertion_cbor(&client_data_hash, RP_ID);

    println!("[2.2] Calling authenticatorGetAssertion...");

    // Prepare CTAP command: command byte (0x02) + CBOR parameters
    let mut ctap_request = vec![0x02]; // getAssertion command
    ctap_request.extend_from_slice(&get_assertion_request);

    // Call authenticator with the full CTAP request
    let mut response = Vec::new();
    auth.handle(&ctap_request, &mut response)?;

    // Parse response - first byte is status, rest is CBOR
    if response.is_empty() {
        eprintln!("❌ Empty response from getAssertion");
        return Err(keylib::common::Error::Other);
    }

    let status = response[0];
    if status != 0x00 {
        eprintln!("❌ getAssertion failed with status: 0x{:02x}", status);
        return Err(keylib::common::Error::Other);
    }

    println!("      ✓ Assertion obtained successfully\n");

    // Success!
    println!("╔════════════════════════════════════════════════╗");
    println!("║         ✓ Flow Completed Successfully          ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("Summary:");
    println!("  • Registered new credential for alice@example.com");
    println!("  • Successfully authenticated using the credential");
    println!("  • All operations performed in-memory (no USB required)");
    println!("  • Credentials stored: {}", credentials.lock().unwrap().len());

    Ok(())
}

/// Compute PIN hash (SHA-256)
fn compute_pin_hash(pin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pin.as_bytes());
    hasher.finalize().into()
}

/// Compute clientDataHash from a challenge
fn compute_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> Vec<u8> {
    let client_data_json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        base64::prelude::BASE64_STANDARD.encode(challenge),
        origin
    );
    Sha256::digest(client_data_json.as_bytes()).to_vec()
}

/// Build makeCredential CBOR request
fn build_make_credential_cbor(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    use ciborium::Value;

    // Build RP map
    let rp_map = vec![
        (Value::Text("id".to_string()), Value::Text(rp_id.to_string())),
        (Value::Text("name".to_string()), Value::Text(rp_name.to_string())),
    ];

    // Build user map
    let user_map = vec![
        (Value::Text("id".to_string()), Value::Bytes(user_id.to_vec())),
        (Value::Text("name".to_string()), Value::Text(user_name.to_string())),
        (Value::Text("displayName".to_string()), Value::Text(user_display_name.to_string())),
    ];

    // Build pubKeyCredParams - ES256 algorithm
    let pub_key_params = vec![
        Value::Map(vec![
            (Value::Text("type".to_string()), Value::Text("public-key".to_string())),
            (Value::Text("alg".to_string()), Value::Integer((-7).into())),  // ES256
        ])
    ];

    // Build options map
    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(true)),  // resident key
        (Value::Text("uv".to_string()), Value::Bool(true)),  // user verification
    ];

    // Build main request map (keys are integers per CTAP spec)
    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Bytes(client_data_hash.to_vec())),  // clientDataHash
        (Value::Integer(0x02.into()), Value::Map(rp_map)),                       // rp
        (Value::Integer(0x03.into()), Value::Map(user_map)),                     // user
        (Value::Integer(0x04.into()), Value::Array(pub_key_params)),             // pubKeyCredParams
        (Value::Integer(0x07.into()), Value::Map(options_map)),                  // options
    ];

    let mut buffer = Vec::new();
    ciborium::into_writer(&Value::Map(request_map), &mut buffer).expect("CBOR encoding");
    buffer
}

/// Build getAssertion CBOR request
fn build_get_assertion_cbor(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
    use ciborium::Value;

    // Build options map
    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)),  // user presence
        (Value::Text("uv".to_string()), Value::Bool(true)),  // user verification
    ];

    // Build main request map (keys are integers per CTAP spec)
    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Text(rp_id.to_string())),           // rpId
        (Value::Integer(0x02.into()), Value::Bytes(client_data_hash.to_vec())),  // clientDataHash
        (Value::Integer(0x05.into()), Value::Map(options_map)),                  // options
    ];

    let mut buffer = Vec::new();
    ciborium::into_writer(&Value::Map(request_map), &mut buffer).expect("CBOR encoding");
    buffer
}
