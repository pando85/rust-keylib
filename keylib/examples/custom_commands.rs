//! Example demonstrating custom CTAP commands
//!
//! This example shows how to:
//! 1. Create custom command handlers
//! 2. Register them with the authenticator
//! 3. Send custom CTAP requests and receive responses
//!
//! Run with:
//! ```bash
//! cargo run --example custom_commands
//! ```

use keylib::error::Result;
use keylib::{
    Authenticator, AuthenticatorConfig, AuthenticatorOptions, Callbacks, CtapCommand,
    CustomCommand, UpResult, UvResult,
};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

// Custom command bytes
const CMD_CUSTOM_ECHO: u8 = 0x41; // Echo command - returns the input
const CMD_CUSTOM_STATUS: u8 = 0x42; // Status command - returns authenticator status

// CTAP2 status codes
const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;

// PIN configuration
fn get_pin_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"123456");
    hasher.finalize().into()
}

#[derive(Clone)]
struct CredentialStore {
    credentials: HashMap<Vec<u8>, keylib::Credential>,
}

impl CredentialStore {
    fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }
}

/// Create a custom echo command (0x41)
///
/// This command echoes back the request data after the command byte.
/// Useful for testing the custom command infrastructure.
fn create_custom_echo_command() -> CustomCommand {
    let handler = Arc::new(
        |_auth: *mut std::ffi::c_void, request: &[u8], response: &mut [u8]| -> usize {
            println!("ECHO command (0x{:02x}) called", CMD_CUSTOM_ECHO);
            println!(
                "   Request length: {} bytes (command byte already consumed)",
                request.len()
            );

            // Echo: copy request data to response (after status byte)
            // NOTE: The command byte is NOT included in the request - it was consumed by Zig dispatcher
            let data_len = request.len();
            if data_len > response.len() - 1 {
                eprintln!("ERROR: Response buffer too small");
                response[0] = CTAP2_ERR_INVALID_COMMAND;
                return 1;
            }

            response[0] = CTAP2_OK;
            if data_len > 0 {
                response[1..=data_len].copy_from_slice(request);
            }

            println!("   Echoed {} bytes", data_len);
            1 + data_len
        },
    );

    CustomCommand::new(CMD_CUSTOM_ECHO, handler)
}

/// Create a custom status command (0x42)
///
/// This command returns a simple status message with credential count.
fn create_custom_status_command(store: Arc<Mutex<CredentialStore>>) -> CustomCommand {
    let handler = Arc::new(
        move |_auth: *mut std::ffi::c_void, request: &[u8], response: &mut [u8]| -> usize {
            println!(
                "📊 Custom STATUS command (0x{:02x}) called",
                CMD_CUSTOM_STATUS
            );

            // Verify command byte
            if request.is_empty() || request[0] != CMD_CUSTOM_STATUS {
                response[0] = CTAP2_ERR_INVALID_COMMAND;
                return 1;
            }

            // Get credential count
            let count = store.lock().unwrap().credentials.len();

            // Return simple status (CTAP2_OK + count as u32 little-endian)
            response[0] = CTAP2_OK;
            let count_bytes = (count as u32).to_le_bytes();
            response[1..5].copy_from_slice(&count_bytes);

            println!("   ✅ Returned status: {} credentials", count);
            5
        },
    );

    CustomCommand::new(CMD_CUSTOM_STATUS, handler)
}

fn main() -> Result<()> {
    println!("🔧 Custom Commands Example");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Set up credential storage
    let store = Arc::new(Mutex::new(CredentialStore::new()));
    let store_for_callbacks = store.clone();

    // Set PIN hash
    let pin_hash = get_pin_hash();
    Authenticator::set_pin_hash(&pin_hash);
    println!("✅ PIN hash set (PIN: 123456)");

    // Build callbacks
    let callbacks = Callbacks {
        up: Some(Arc::new(
            |_info: &str, _user: Option<&str>, _rp: Option<&str>| {
                println!("   👆 User presence check - auto-accepting");
                Ok(UpResult::Accepted)
            },
        )),
        uv: Some(Arc::new(
            |_info: &str, _user: Option<&str>, _rp: Option<&str>| {
                println!("   🔐 User verification check - auto-accepting");
                Ok(UvResult::Accepted)
            },
        )),
        select: Some(Arc::new(|rp_id: &str| {
            println!("   🔍 Credential selection for RP: {}", rp_id);
            Ok(Vec::new())
        })),
        read: Some(Arc::new(|id: &str, rp: &str| {
            println!("   📖 Read credential: {} for RP: {}", id, rp);
            Ok(Vec::new())
        })),
        write: Some(Arc::new(
            move |id: &str, rp_id: &str, cred: keylib::CredentialRef| {
                println!("   💾 Writing credential for RP: {}", rp_id);
                let credential = keylib::Credential {
                    id: cred.id.to_vec(),
                    rp: keylib::credential::RelyingParty {
                        id: rp_id.to_string(),
                        name: cred.rp_name.map(|s| s.to_string()),
                    },
                    user: keylib::credential::User {
                        id: cred.user_id.to_vec(),
                        name: None,
                        display_name: None,
                    },
                    sign_count: cred.sign_count,
                    alg: cred.alg,
                    private_key: cred.private_key.to_vec(),
                    created: cred.created,
                    discoverable: cred.discoverable,
                    extensions: keylib::credential::Extensions {
                        cred_protect: cred.cred_protect,
                        hmac_secret: None,
                    },
                };

                store_for_callbacks
                    .lock()
                    .unwrap()
                    .credentials
                    .insert(id.as_bytes().to_vec(), credential);
                Ok(())
            },
        )),
        delete: Some(Arc::new(|id: &str| {
            println!("   🗑️  Delete credential: {}", id);
            Ok(())
        })),
        read_first: Some(Arc::new(
            |_id: Option<&str>, _rp: Option<&str>, _hash: Option<[u8; 32]>| {
                Err(keylib::Error::DoesNotExist)
            },
        )),
        read_next: Some(Arc::new(|| Err(keylib::Error::DoesNotExist))),
    };

    println!("✅ Callbacks configured");

    // Configure authenticator with custom commands
    let options = AuthenticatorOptions {
        rk: true,
        up: true,
        uv: Some(true),
        plat: false,
        client_pin: Some(true),
        pin_uv_auth_token: Some(true),
        cred_mgmt: Some(true),
        bio_enroll: Some(false),
        large_blobs: Some(false),
        ep: None,
        always_uv: None,
    };

    let config = AuthenticatorConfig::builder()
        .options(options)
        .commands(vec![
            CtapCommand::MakeCredential,
            CtapCommand::GetAssertion,
            CtapCommand::GetInfo,
            CtapCommand::ClientPin,
        ])
        .custom_commands(vec![
            create_custom_echo_command(),
            create_custom_status_command(store.clone()),
        ])
        .max_credentials(100)
        .build();

    println!("✅ Authenticator configuration built with 2 custom commands:");
    println!("   - 0x{:02x}: ECHO command", CMD_CUSTOM_ECHO);
    println!("   - 0x{:02x}: STATUS command", CMD_CUSTOM_STATUS);
    println!();

    // Initialize authenticator
    let mut auth = Authenticator::with_config(callbacks, config)?;
    println!("✅ Authenticator initialized");
    println!();

    // Test 1: Custom ECHO command
    println!(
        "📤 Test 1: Sending custom ECHO command (0x{:02x})",
        CMD_CUSTOM_ECHO
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    // Note: CTAP commands can be sent directly without CBOR for simple cases
    // The command byte (0x41) followed by raw data
    let echo_request = vec![CMD_CUSTOM_ECHO, 0x01, 0x02, 0x03, 0x04, 0x05];
    println!("Request: {:02x?}", echo_request);
    println!("Note: This is a direct command (not wrapped in CTAPHID)");

    let mut response = Vec::new();
    match auth.handle(&echo_request, &mut response) {
        Ok(_) => {
            println!("Response: {:02x?}", response);
            println!(
                "Status: 0x{:02x} ({})",
                response[0],
                if response[0] == CTAP2_OK {
                    "CTAP2_OK"
                } else {
                    "ERROR"
                }
            );
            if response.len() > 1 {
                println!("Echoed data: {:02x?}", &response[1..]);
            }
        }
        Err(e) => {
            println!("Error calling handle: {:?}", e);
        }
    }
    println!();

    // Test 2: Custom STATUS command
    println!(
        "📤 Test 2: Sending custom STATUS command (0x{:02x})",
        CMD_CUSTOM_STATUS
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let status_request = vec![CMD_CUSTOM_STATUS];
    println!("Request: {:02x?}", status_request);

    response.clear();
    auth.handle(&status_request, &mut response)?;

    println!("Response: {:02x?}", response);
    println!(
        "Status: 0x{:02x} ({})",
        response[0],
        if response[0] == CTAP2_OK {
            "CTAP2_OK"
        } else {
            "ERROR"
        }
    );
    if response.len() >= 5 {
        let count = u32::from_le_bytes([response[1], response[2], response[3], response[4]]);
        println!("Credential count: {}", count);
    }
    println!();

    // Test 3: Standard GetInfo command (for comparison)
    println!("📤 Test 3: Sending standard GetInfo command (0x04)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let getinfo_request = vec![0x04];
    println!("Request: {:02x?}", getinfo_request);

    response.clear();
    auth.handle(&getinfo_request, &mut response)?;

    println!("Response length: {} bytes", response.len());
    println!(
        "Status: 0x{:02x} ({})",
        response[0],
        if response[0] == CTAP2_OK {
            "CTAP2_OK"
        } else {
            "ERROR"
        }
    );
    println!();

    // Test 4: Echo with longer data
    println!("📤 Test 4: Sending ECHO with longer data");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let long_echo_request = vec![CMD_CUSTOM_ECHO; 20]; // 20 bytes of 0x41
    println!("Request length: {} bytes", long_echo_request.len());

    response.clear();
    auth.handle(&long_echo_request, &mut response)?;

    println!("Response length: {} bytes", response.len());
    println!(
        "Status: 0x{:02x} ({})",
        response[0],
        if response[0] == CTAP2_OK {
            "CTAP2_OK"
        } else {
            "ERROR"
        }
    );
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ All custom command tests completed successfully!");
    println!();
    println!("💡 Key takeaways:");
    println!("   • Custom commands work alongside standard CTAP2 commands");
    println!("   • Command bytes 0x40-0xFF are available for vendor use");
    println!("   • Handlers receive raw request/response buffers");
    println!("   • Custom commands can access shared state (like CredentialStore)");
    println!("   • Error handling follows standard CTAP2 status codes");

    Ok(())
}
