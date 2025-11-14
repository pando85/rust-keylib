//! Complete WebAuthn Flow Example
//!
//! This example demonstrates a full WebAuthn registration and authentication flow:
//! 1. Register a new credential (makeCredential)
//! 2. Authenticate using the registered credential (getAssertion)
//!
//! # Prerequisites
//! - Virtual authenticator running (see authenticator example)
//! - Authenticator configured with PIN "123456"
//!
//! # Usage
//! ```bash
//! # Terminal 1: Start authenticator
//! cargo run --example authenticator
//!
//! # Terminal 2: Run complete flow
//! cargo run --example webauthn_flow
//! ```

use keylib::client::{
    Client, ClientDataHash, GetAssertionRequest, MakeCredentialRequest, PinUvAuth,
    PinUvAuthProtocol, TransportList, User,
};
use keylib::client_pin::{PinProtocol, PinUvAuthEncapsulation};
use keylib::credential::RelyingParty;
use keylib::error::Result;
use sha2::{Digest, Sha256};

const PIN: &str = "123456";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║   Complete WebAuthn Registration & Auth Flow   ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    println!("📱 [1/2] REGISTRATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    // Connect to authenticator
    println!("[1.1] Looking for FIDO2 authenticators...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        eprintln!("❌ No authenticators found. Please start the authenticator example first.");
        eprintln!("   Run: cargo run --example authenticator");
        return Err(keylib::Error::Other);
    }

    println!("      ✓ Found {} authenticator(s)", list.len());

    let mut transport = list.get(0).ok_or(keylib::Error::Other)?;
    transport.open()?;
    println!("      ✓ Transport opened successfully\n");

    // Establish PIN protocol for registration
    println!("[1.2] Establishing PIN protocol V2...");
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;
    println!("      ✓ Key agreement successful\n");

    // Get PIN token with makeCredential permission
    println!("[1.3] Getting PIN token (using PIN: {})...", PIN);
    let permissions = 0x01; // makeCredential permission (mc)

    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        permissions,
        Some(RP_ID),
    )?;

    println!("      ✓ PIN token retrieved ({} bytes)\n", pin_token.len());

    // Prepare credential creation parameters
    println!("[1.4] Preparing credential creation...");

    // Generate WebAuthn client data
    let challenge = generate_random_bytes::<32>();
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64_url::encode(&challenge),
        ORIGIN
    );

    let client_data_hash = Sha256::digest(client_data.as_bytes());

    // Convert to ClientDataHash (validates 32-byte length)
    let client_data_hash = ClientDataHash::from_slice(&client_data_hash)?;

    // Relying party information
    let rp = RelyingParty {
        id: RP_ID.to_string(),
        name: Some("Example Corporation".to_string()),
    };

    // User information
    let user = User {
        id: vec![1, 2, 3, 4], // User ID (should be unique per user)
        name: "alice@example.com".to_string(),
        display_name: Some("Alice".to_string()),
    };

    println!("      RP: {}", rp.id);
    println!("      User: {}", user.name);

    // Compute PIN/UV auth parameter
    let pin_uv_auth_param = encapsulation.authenticate(client_data_hash.as_slice(), &pin_token)?;
    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);
    println!("      ✓ Auth parameter computed\n");

    // Create credential using the new builder API
    println!("[1.5] Creating credential (makeCredential)...");
    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    let attestation_object = Client::make_credential(&mut transport, request)?;

    println!(
        "      ✓ Credential created ({} bytes)",
        attestation_object.len()
    );

    // ============================================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ============================================================
    println!();
    println!("{}", "═".repeat(48));
    println!();
    println!("📱 [2/2] AUTHENTICATION PHASE");
    println!("{}", "═".repeat(48));
    println!();

    // Establish PIN protocol for authentication
    println!("[2.1] Setting up PIN protocol V2...");
    let mut pin_protocol = PinUvAuthEncapsulation::new(&mut transport, protocol)?;
    println!("      ✓ PIN protocol established\n");

    // Get PIN token with getAssertion permission
    println!("[2.2] Getting PIN token with getAssertion permission...");
    let pin_token = pin_protocol.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        PIN,
        0x02, // getAssertion permission (ga)
        Some(RP_ID),
    )?;
    println!("      ✓ PIN token retrieved ({} bytes)\n", pin_token.len());

    // Build client data for authentication
    println!("[2.3] Building WebAuthn client data...");
    let challenge = generate_random_bytes::<32>();
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        base64_url::encode(&challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data.as_bytes());
    let client_data_hash = ClientDataHash::from_slice(&client_data_hash)?;
    println!("      ✓ Client data hash computed\n");

    // Calculate PIN/UV auth parameter
    println!("[2.4] Calculating PIN/UV auth parameter...");
    let pin_uv_auth_param = pin_protocol.authenticate(client_data_hash.as_slice(), &pin_token)?;
    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);
    println!("      ✓ Auth parameter computed\n");

    // Send authenticatorGetAssertion using the new builder API
    println!("[2.5] Sending authenticatorGetAssertion...");
    let request = GetAssertionRequest::new(client_data_hash, RP_ID)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    let response = Client::get_assertion(&mut transport, request)?;

    println!(
        "      ✓ Authentication successful ({} bytes)\n",
        response.len()
    );

    // Parse the CBOR response
    println!("[2.6] Parsing assertion response...");
    match ciborium::from_reader::<ciborium::value::Value, _>(response.as_slice()) {
        Ok(cbor) => {
            if let ciborium::value::Value::Map(map) = cbor {
                println!("      Response contains:");
                for (key, value) in map {
                    if let ciborium::value::Value::Integer(i) = key {
                        let key_num: i128 = i.into();
                        let key_name = match key_num {
                            1 => "credential",
                            2 => "authData",
                            3 => "signature",
                            4 => "user",
                            5 => "numberOfCredentials",
                            _ => "unknown",
                        };
                        match value {
                            ciborium::value::Value::Bytes(b) => {
                                println!("        • {}: {} bytes", key_name, b.len());
                            }
                            ciborium::value::Value::Map(m) => {
                                println!("        • {}: {} entries", key_name, m.len());
                            }
                            ciborium::value::Value::Integer(n) => {
                                let num: i128 = n.into();
                                println!("        • {}: {}", key_name, num);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("      ⚠ Failed to parse CBOR: {}", e);
        }
    }

    println!();
    println!("╔════════════════════════════════════════════════╗");
    println!("║              ✓ Flow Completed!                 ║");
    println!("╚════════════════════════════════════════════════╝");

    Ok(())
}

// Helper function for base64url encoding
mod base64_url {
    pub fn encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }
}

// Generate random bytes (using system randomness)
fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut bytes = [0u8; N];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Simple pseudo-random generation for demo purposes
    // In production, use a proper CSPRNG like rand crate
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = ((timestamp.wrapping_add(i as u128)) % 256) as u8;
    }

    bytes
}
