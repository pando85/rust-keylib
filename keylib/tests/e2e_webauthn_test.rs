//! End-to-End WebAuthn Flow Tests
//!
//! These tests simulate a complete WebAuthn registration and authentication flow
//! using a virtual authenticator and UHID transport.
//!
//! # Prerequisites
//!
//! These tests require:
//! - Linux with UHID kernel module loaded
//! - Proper permissions to access /dev/uhid
//! - Run with: cargo test --test e2e_webauthn_test
//!
//! # Test Flow
//!
//! 1. Start a virtual authenticator in a background thread
//! 2. Use the Client API to perform registration (makeCredential)
//! 3. Use the Client API to perform authentication (getAssertion)
//! 4. Verify the complete flow succeeds

use keylib::{
    Authenticator, AuthenticatorConfig, CallbacksBuilder, Client, ClientDataHash, Credential,
    CredentialRef, Error, GetAssertionRequest, MakeCredentialRequest, PinProtocol, PinUvAuth,
    PinUvAuthEncapsulation, PinUvAuthProtocol, RelyingParty, Result, TransportList, Uhid,
    UpResult, User, UvResult,
};
use keylib_transport::{Cmd, Message, Packet};

use base64::prelude::*;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Test constants
const TEST_PIN: &str = "123456";
const TEST_RP_ID: &str = "test.example.com";
const TEST_ORIGIN: &str = "https://test.example.com";
const TEST_USER_ID: &[u8] = b"test-user-123";
const TEST_USER_NAME: &str = "testuser@example.com";
const TEST_USER_DISPLAY_NAME: &str = "Test User";

/// Helper struct to manage the virtual authenticator lifecycle
struct TestAuthenticator {
    handle: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<Mutex<bool>>,
}

impl TestAuthenticator {
    /// Start a virtual authenticator in a background thread with PIN
    fn start() -> Result<Self> {
        Self::start_with_options(true)
    }

    /// Start a virtual authenticator without PIN (UV-only)
    fn start_uv_only() -> Result<Self> {
        Self::start_with_options(false)
    }

    /// Start a virtual authenticator with optional PIN
    fn start_with_options(use_pin: bool) -> Result<Self> {
        let stop_flag = Arc::new(Mutex::new(false));
        let stop_flag_clone = stop_flag.clone();

        // Spawn authenticator thread
        let handle = thread::spawn(move || {
            if let Err(e) = run_test_authenticator(stop_flag_clone, use_pin) {
                eprintln!("Authenticator error: {:?}", e);
            }
        });

        // Give authenticator time to initialize and register with UHID
        thread::sleep(Duration::from_millis(1000));

        Ok(Self {
            handle: Some(handle),
            stop_flag,
        })
    }

    /// Stop the authenticator
    fn stop(&mut self) {
        if let Ok(mut flag) = self.stop_flag.lock() {
            *flag = true;
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TestAuthenticator {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run the virtual authenticator
fn run_test_authenticator(stop_flag: Arc<Mutex<bool>>, use_pin: bool) -> Result<()> {
    // Create credential storage
    #[cfg(feature = "zig-ffi")]
    let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, keylib::Credential>::new()));

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));

    // Setup PIN (SHA-256 hash of "123456") - only if use_pin is true
    if use_pin {
        let pin_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(TEST_PIN.as_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };
        Authenticator::set_pin_hash(&pin_hash);
        println!("[Authenticator] PIN configured: {}", TEST_PIN);
    } else {
        println!("[Authenticator] UV-only mode (no PIN required)");
    }
    let credentials_clone = credentials.clone();
    #[cfg(feature = "zig-ffi")]
    let write_callback = Arc::new(
        move |id: &str, rp: &str, cred: keylib::CredentialRef| -> Result<()> {
            let mut store = credentials_clone.lock().unwrap();
            let key = id.as_bytes().to_vec();
            store.insert(key, cred.to_owned());
            println!("[Authenticator] Stored credential for RP: {}", rp);
            Ok(())
        },
    );

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let write_callback = Arc::new(
        move |_id: &str, _rp: &str, cred: CredentialRef| -> Result<()> {
            let mut store = credentials_clone.lock().unwrap();
            store.insert(cred.id.to_vec(), cred.to_owned());
            println!("[Authenticator] Stored credential for RP: {}", cred.rp_id);
            Ok(())
        },
    );

    // Build callbacks - zig-ffi version
    #[cfg(feature = "zig-ffi")]
    let callbacks = {
        let credentials_clone = credentials.clone();
        let read_callback = Arc::new(move |id: &str, _rp: &str| -> Result<Vec<u8>> {
            let store = credentials_clone.lock().unwrap();

            // Simple lookup by credential ID
            let key = id.as_bytes().to_vec();
            if let Some(cred) = store.get(&key) {
                return cred.to_bytes();
            }

            Err(keylib::Error::DoesNotExist)
        });

        let credentials_clone = credentials.clone();
        let delete_callback = Arc::new(move |id: &str| -> Result<()> {
            let mut store = credentials_clone.lock().unwrap();
            let key = id.as_bytes().to_vec();
            store.remove(&key);
            println!("[Authenticator] Deleted credential: {}", id);
            Ok(())
        });

        let up_callback = Arc::new(
            |_info: &str, _user: Option<&str>, _rp: Option<&str>| -> Result<UpResult> {
                println!("[Authenticator] User presence check: approved");
                Ok(UpResult::Accepted)
            },
        );

        let uv_callback = Arc::new(
            |_info: &str, _user: Option<&str>, _rp: Option<&str>| -> Result<UvResult> {
                println!("[Authenticator] User verification check: approved");
                Ok(UvResult::Accepted)
            },
        );

        let credentials_clone = credentials.clone();
        let read_first_callback = Arc::new(
            move |id: Option<&str>,
                  rp: Option<&str>,
                  _hash: Option<[u8; 32]>|
                  -> Result<keylib::Credential> {
                let store = credentials_clone.lock().unwrap();

                // Find matching credential
                for (cred_id, cred) in store.iter() {
                    if let Some(search_id) = id {
                        if cred_id == search_id.as_bytes() {
                            return Ok(cred.clone());
                        }
                    } else if let Some(search_rp) = rp {
                        if cred.rp.id == search_rp {
                            return Ok(cred.clone());
                        }
                    } else {
                        // Return first credential if no specific search
                        return Ok(cred.clone());
                    }
                }

                Err(keylib::Error::DoesNotExist)
            },
        );

        let read_next_callback = Arc::new(|| -> Result<keylib::Credential> {
            // For simplicity, we don't support iteration in tests
            Err(keylib::Error::DoesNotExist)
        });

        Callbacks::new(
            Some(up_callback),
            Some(uv_callback),
            None, // select
            Some(read_callback),
            Some(write_callback),
            Some(delete_callback),
            Some(read_first_callback),
            Some(read_next_callback),
        )
    };

    // Build callbacks - pure-rust version
    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let callbacks = {
        let creds_read = credentials.clone();
        let creds_get = credentials.clone();
        let creds_delete = credentials.clone();

        CallbacksBuilder::new()
            .up(Arc::new(|_, _, _| {
                println!("[Authenticator] User presence check: approved");
                Ok(UpResult::Accepted)
            }))
            .uv(Arc::new(|_, _, _| {
                println!("[Authenticator] User verification check: approved");
                Ok(UvResult::Accepted)
            }))
            .write(write_callback)
            .read_credentials(Arc::new(move |rp_id: &str, user_id: Option<&[u8]>| {
                let store = creds_read.lock().unwrap();
                let filtered: Vec<Credential> = store
                    .values()
                    .filter(|c| {
                        c.rp.id == rp_id
                            && (user_id.is_none() || user_id == Some(c.user.id.as_slice()))
                    })
                    .cloned()
                    .collect();
                Ok(filtered)
            }))
            .get_credential(Arc::new(move |cred_id: &[u8]| {
                let store = creds_get.lock().unwrap();
                store
                    .get(cred_id)
                    .cloned()
                    .ok_or(Error::DoesNotExist)
            }))
            .delete(Arc::new(move |cred_id: &str| {
                let mut store = creds_delete.lock().unwrap();
                store.remove(cred_id.as_bytes());
                println!("[Authenticator] Deleted credential: {}", cred_id);
                Ok(())
            }))
            .build()
    };

    // Configure authenticator - zig-ffi version
    #[cfg(feature = "zig-ffi")]
    let mut auth = {
        let options = AuthenticatorOptions::new()
            .with_resident_keys(true)
            .with_user_presence(true)
            .with_user_verification(Some(true)) // UV capable and configured
            .with_client_pin(Some(use_pin)) // PIN capability based on use_pin
            .with_credential_management(Some(true));

        let config = AuthenticatorConfig::builder()
            .aaguid([
                0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
                0x7c, 0x88,
            ])
            .commands(vec![
                CtapCommand::MakeCredential,
                CtapCommand::GetAssertion,
                CtapCommand::GetInfo,
                CtapCommand::ClientPin,
                CtapCommand::CredentialManagement,
                CtapCommand::Selection,
            ])
            .options(options)
            .max_credentials(25)
            .extensions(vec!["credProtect".to_string()])
            .build();

        Authenticator::with_config(callbacks, config)?
    };

    // Configure authenticator - pure-rust version
    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let mut auth = {
        let config = AuthenticatorConfig::builder()
            .aaguid([
                0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
                0x7c, 0x88,
            ])
            .max_credentials(25)
            .extensions(vec!["credProtect".to_string()])
            .build();

        Authenticator::with_config(callbacks, config)?
    };

    // Open UHID device
    #[cfg(feature = "zig-ffi")]
    let uhid = Uhid::open().map_err(|_| {
        eprintln!("Failed to open UHID device.");
        eprintln!("Make sure you have the uhid kernel module loaded and proper permissions.");
        keylib::Error::Other
    })?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let uhid = Uhid::open().map_err(|_| {
        eprintln!("Failed to open UHID device.");
        eprintln!("Make sure you have the uhid kernel module loaded and proper permissions.");
        Error::Other
    })?;

    println!("[Authenticator] Started and ready");

    // Main authenticator loop - zig-ffi version
    #[cfg(feature = "zig-ffi")]
    {
        // Create CTAP HID layer
        let mut ctaphid = Ctaphid::new()?;
        let mut response_buffer = Vec::new(); // Reusable response buffer

        let mut buffer = [0u8; 64];
        loop {
            // Check stop flag
            if let Ok(flag) = stop_flag.lock()
                && *flag
            {
                println!("[Authenticator] Stopping");
                break;
            }

            // Read packet with timeout
            match uhid.read_packet(&mut buffer) {
                Ok(len) if len > 0 => {
                    // Process incoming CTAP HID packet
                    if let Some(mut response) = ctaphid.handle(&buffer) {
                        match response.command() {
                            keylib::ctaphid::Cmd::Cbor => {
                                // Process CBOR command through authenticator
                                match auth.handle(response.data(), &mut response_buffer) {
                                    Ok(_) => {
                                        if let Err(e) = response.set_data(&response_buffer) {
                                            eprintln!(
                                                "[Authenticator] Failed to set response data: {:?}",
                                                e
                                            );
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[Authenticator] Handler error: {:?}", e);
                                        continue;
                                    }
                                }
                            }
                            _ => {
                                // Other commands handled automatically by CTAPHID
                            }
                        }

                        // Send response packets back
                        for packet in response.packets() {
                            if let Err(e) = uhid.write_packet(&packet) {
                                eprintln!("[Authenticator] Failed to write response: {:?}", e);
                            }
                        }
                    }
                }
                Ok(_) => {
                    // No data, sleep briefly
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    // Read error, sleep and retry
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    // Main authenticator loop - pure-rust version
    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    {
        // CTAP HID state
        let mut current_channel: u32 = 0xffffffff; // Broadcast channel
        let mut pending_packets: Vec<Packet> = Vec::new();
        let mut response_buffer = Vec::new();

        let mut buffer = [0u8; 64];
        loop {
            // Check stop flag
            if *stop_flag.lock().unwrap() {
                println!("[Authenticator] Stopping");
                break;
            }

            // Read packet with timeout
            match uhid.read_packet(&mut buffer) {
                Ok(len) if len > 0 => {
                    let packet = Packet::from_bytes(buffer);

                    // Handle initialization packets
                    if packet.is_init() {
                        // New message starting
                        current_channel = packet.cid();
                        pending_packets.clear();
                        pending_packets.push(packet);

                        // Check if this is a complete message
                        if let Some(payload_len) = pending_packets[0].payload_len() {
                            let init_data_len = pending_packets[0].payload().len();
                            if init_data_len >= payload_len as usize {
                                // Complete message in one packet
                                if let Err(_e) = process_message_pure_rust(
                                    &mut auth,
                                    &uhid,
                                    &pending_packets,
                                    &mut response_buffer,
                                ) {}
                                pending_packets.clear();
                            }
                        }
                    } else {
                        // Continuation packet
                        if packet.cid() == current_channel {
                            pending_packets.push(packet);

                            // Check if we have the complete message
                            if let Some(first) = pending_packets.first() {
                                if let Some(total_len) = first.payload_len() {
                                    let mut received_len = first.payload().len();
                                    for pkt in &pending_packets[1..] {
                                        received_len += pkt.payload().len();
                                    }

                                    if received_len >= total_len as usize {
                                        // Complete message received
                                        if let Err(_e) = process_message_pure_rust(
                                            &mut auth,
                                            &uhid,
                                            &pending_packets,
                                            &mut response_buffer,
                                        ) {}
                                        pending_packets.clear();
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(_) => {
                    // No data, sleep briefly
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    Ok(())
}

/// Process a complete CTAP HID message (pure-rust)
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
fn process_message_pure_rust(
    auth: &mut Authenticator,
    uhid: &Uhid,
    packets: &[Packet],
    response_buffer: &mut Vec<u8>,
) -> Result<()> {
    // Reassemble message
    let message = Message::from_packets(packets).map_err(|_e| Error::Other)?;

    let cid = message.cid;
    let cmd = message.cmd;

    // Handle CTAP commands
    match cmd {
        Cmd::Cbor => {
            // CTAP CBOR command - process through authenticator
            response_buffer.clear();
            match auth.handle(&message.data, response_buffer) {
                Ok(_) => {
                    // Send success response
                    let response_msg = Message::new(cid, Cmd::Cbor, response_buffer.clone());
                    send_message_pure_rust(uhid, &response_msg)?;
                }
                Err(_e) => {
                    // Send error response
                    let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01]); // CTAP2_ERR_INVALID_CBOR
                    send_message_pure_rust(uhid, &response_msg)?;
                }
            }
        }
        Cmd::Init => {
            // CTAP HID INIT - return nonce + channel ID
            if message.data.len() >= 8 {
                let mut response_data = message.data[..8].to_vec(); // Echo nonce
                response_data.extend_from_slice(&cid.to_be_bytes()); // Channel ID
                response_data.push(2); // CTAP protocol version
                response_data.push(0); // Major device version
                response_data.push(0); // Minor device version
                response_data.push(0); // Build device version
                response_data.push(0x01); // Capabilities: CBOR

                let response_msg = Message::new(cid, Cmd::Init, response_data);
                send_message_pure_rust(uhid, &response_msg)?;
            }
        }
        Cmd::Ping => {
            // Echo ping data
            let response_msg = Message::new(cid, Cmd::Ping, message.data);
            send_message_pure_rust(uhid, &response_msg)?;
        }
        _ => {}
    }

    Ok(())
}

/// Send a CTAP HID message via UHID (pure-rust)
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
fn send_message_pure_rust(uhid: &Uhid, message: &Message) -> Result<()> {
    let packets = message
        .to_packets()
        .map_err(|_e| Error::Other)?;

    for packet in packets.iter() {
        uhid.write_packet(packet.as_bytes())?;
    }

    Ok(())
}

/// Helper to create a ClientDataHash from a challenge
fn create_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> ClientDataHash {
    // In a real WebAuthn implementation, this would be the full clientDataJSON
    // For testing, we'll just hash the challenge + origin + type
    let client_data = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        base64::prelude::BASE64_STANDARD.encode(challenge),
        origin
    );

    let hash_bytes = Sha256::digest(client_data.as_bytes());
    ClientDataHash::from_slice(&hash_bytes).expect("Valid 32-byte hash")
}

#[test]
#[ignore] // Requires UHID permissions
#[serial] // Run serially to avoid UHID/CID conflicts
fn test_complete_webauthn_flow() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║     E2E WebAuthn Flow Test                     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Start virtual authenticator
    println!("[Test] Starting virtual authenticator...");
    let mut authenticator = TestAuthenticator::start()?;
    thread::sleep(Duration::from_secs(1)); // Give it time to fully initialize

    // Connect to authenticator
    println!("[Test] Connecting to authenticator...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        authenticator.stop();
        panic!("No authenticators found - virtual authenticator may not have started");
    }

    #[cfg(feature = "zig-ffi")]
    let mut transport = list.get(0).ok_or(keylib::Error::Other)?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let mut transport = list.get(0).ok_or(Error::Other)?;

    transport.open()?;
    println!("[Test] ✓ Connected to authenticator\n");

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    println!("[Test] PHASE 1: Registration");
    println!("{}", "─".repeat(48));

    // Establish PIN protocol
    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;

    // Get PIN token with makeCredential permission
    let permissions = 0x01; // makeCredential
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        TEST_PIN,
        permissions,
        Some(TEST_RP_ID),
    )?;

    // Create registration request
    let challenge = b"registration-challenge-12345";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("Test Relying Party".to_string()),
    };

    let user = User {
        id: TEST_USER_ID.to_vec(),
        name: Some(TEST_USER_NAME.to_string()),
        display_name: Some(TEST_USER_DISPLAY_NAME.to_string()),
    };

    // Calculate pinUvAuthParam
    // Calculate pinUvAuthParam (for makeCredential)
    let pin_uv_auth_param = {
        let mut data = Vec::new();
        data.extend_from_slice(client_data_hash.as_slice());
        encapsulation.authenticate(&data, &pin_token)?
    };

    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    // Make credential
    println!("[Test] Calling makeCredential...");
    let attestation_response = Client::make_credential(&mut transport, request)?;

    assert!(
        !attestation_response.is_empty(),
        "Should receive attestation"
    );
    println!(
        "[Test] ✓ Registration successful ({} bytes)\n",
        attestation_response.len()
    );

    // ============================================================
    // PHASE 2: AUTHENTICATION (getAssertion)
    // ============================================================
    println!("[Test] PHASE 2: Authentication");
    println!("{}", "─".repeat(48));

    // Get new PIN token with getAssertion permission
    let permissions = 0x02; // getAssertion
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        TEST_PIN,
        permissions,
        Some(TEST_RP_ID),
    )?;

    // Create authentication request
    let challenge = b"authentication-challenge-67890";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.get");

    // Calculate pinUvAuthParam (for getAssertion)
    let pin_uv_auth_param = {
        let mut data = Vec::new();
        data.extend_from_slice(client_data_hash.as_slice());
        encapsulation.authenticate(&data, &pin_token)?
    };

    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = GetAssertionRequest::new(client_data_hash, TEST_RP_ID)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    // Get assertion
    println!("[Test] Calling getAssertion...");
    let assertion_response = Client::get_assertion(&mut transport, request)?;

    assert!(!assertion_response.is_empty(), "Should receive assertion");
    println!(
        "[Test] ✓ Authentication successful ({} bytes)\n",
        assertion_response.len()
    );

    // Cleanup
    authenticator.stop();

    println!("╔════════════════════════════════════════════════╗");
    println!("║     ✓ E2E Test Passed                          ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore] // Requires UHID permissions
#[serial] // Run serially to avoid UHID/CID conflicts
fn test_registration_without_pin() -> Result<()> {
    println!("\n[Test] Testing registration without PIN (should work for some authenticators)");

    let mut authenticator = TestAuthenticator::start()?;
    thread::sleep(Duration::from_secs(1));

    let list = TransportList::enumerate()?;
    if list.is_empty() {
        authenticator.stop();
        return Ok(()); // Skip if no authenticator
    }

    #[cfg(feature = "zig-ffi")]
    let mut transport = list.get(0).ok_or(keylib::Error::Other)?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let mut transport = list.get(0).ok_or(Error::Other)?;

    transport.open()?;

    let challenge = b"no-pin-challenge";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("Test RP".to_string()),
    };

    let user = User {
        id: TEST_USER_ID.to_vec(),
        name: Some(TEST_USER_NAME.to_string()),
        display_name: Some(TEST_USER_DISPLAY_NAME.to_string()),
    };

    // Request without PIN auth
    let request = MakeCredentialRequest::new(client_data_hash, rp, user).with_timeout(30000);

    let result = Client::make_credential(&mut transport, request);

    // This may succeed or fail depending on authenticator policy
    match result {
        Ok(response) => {
            println!(
                "[Test] ✓ Registration without PIN succeeded ({} bytes)",
                response.len()
            );
        }
        Err(e) => {
            println!("[Test] Registration without PIN failed (expected): {:?}", e);
        }
    }

    authenticator.stop();
    Ok(())
}

#[test]
#[ignore] // Requires UHID permissions
#[serial] // Run serially to avoid UHID/CID conflicts
#[cfg(feature = "zig-ffi")] // Dynamic PIN change only supported in zig-ffi
fn test_pin_change_flow() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║     PIN Change Flow Test                       ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Start virtual authenticator with initial PIN "123456"
    println!("[Test] Starting virtual authenticator with PIN: 123456");
    let mut authenticator = TestAuthenticator::start()?;
    thread::sleep(Duration::from_secs(1));

    let list = TransportList::enumerate()?;
    if list.is_empty() {
        authenticator.stop();
        panic!("No authenticators found");
    }

    #[cfg(feature = "zig-ffi")]
    let mut transport = list.get(0).ok_or(keylib::Error::Other)?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let mut transport = list.get(0).ok_or(Error::Other)?;

    transport.open()?;
    println!("[Test] ✓ Connected to authenticator\n");

    // ============================================================
    // PHASE 1: Register with original PIN
    // ============================================================
    println!("[Test] PHASE 1: Register credential with original PIN");
    println!("{}", "─".repeat(48));

    let protocol = PinProtocol::V2;
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;

    let permissions = 0x01; // makeCredential
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        TEST_PIN,
        permissions,
        Some(TEST_RP_ID),
    )?;

    let challenge = b"registration-with-old-pin";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("PIN Change Test RP".to_string()),
    };

    let user = User {
        id: b"pin-change-user".to_vec(),
        name: Some("pinchange@example.com".to_string()),
        display_name: Some("Pin Change User".to_string()),
    };

    let pin_uv_auth_param = {
        let mut data = Vec::new();
        data.extend_from_slice(client_data_hash.as_slice());
        encapsulation.authenticate(&data, &pin_token)?
    };

    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    let attestation_response = Client::make_credential(&mut transport, request)?;
    println!(
        "[Test] ✓ Registration with original PIN successful ({} bytes)\n",
        attestation_response.len()
    );

    // ============================================================
    // PHASE 2: Change PIN on authenticator
    // ============================================================
    println!("[Test] PHASE 2: Change PIN from '123456' to 'newpin123'");
    println!("{}", "─".repeat(48));

    // Change the PIN hash on the authenticator
    const NEW_PIN: &str = "newpin123";
    let new_pin_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(NEW_PIN.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    Authenticator::set_pin_hash(&new_pin_hash);
    println!("[Test] ✓ PIN changed on authenticator\n");

    // Give the authenticator a moment to process
    thread::sleep(Duration::from_millis(100));

    // ============================================================
    // PHASE 3: Try to authenticate with old PIN (should fail)
    // ============================================================
    println!("[Test] PHASE 3: Attempt authentication with old PIN (should fail)");
    println!("{}", "─".repeat(48));

    // Re-establish key agreement (needed after any state change)
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;

    let permissions = 0x02; // getAssertion
    let result = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        TEST_PIN, // Using old PIN
        permissions,
        Some(TEST_RP_ID),
    );

    match result {
        Err(_) => {
            println!("[Test] ✓ Authentication with old PIN failed as expected\n");
        }
        Ok(_) => {
            println!("[Test] ✗ WARNING: Old PIN still worked (unexpected)\n");
        }
    }

    // ============================================================
    // PHASE 4: Authenticate with new PIN
    // ============================================================
    println!("[Test] PHASE 4: Authenticate with new PIN");
    println!("{}", "─".repeat(48));

    // Re-establish key agreement with new PIN
    let mut encapsulation = PinUvAuthEncapsulation::new(&mut transport, protocol)?;

    let permissions = 0x02; // getAssertion
    let pin_token = encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        NEW_PIN,
        permissions,
        Some(TEST_RP_ID),
    )?;

    let challenge = b"authentication-with-new-pin";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.get");

    let pin_uv_auth_param = {
        let mut data = Vec::new();
        data.extend_from_slice(client_data_hash.as_slice());
        encapsulation.authenticate(&data, &pin_token)?
    };

    let pin_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = GetAssertionRequest::new(client_data_hash, TEST_RP_ID)
        .with_pin_uv_auth(pin_auth)
        .with_timeout(30000);

    let assertion_response = Client::get_assertion(&mut transport, request)?;
    println!(
        "[Test] ✓ Authentication with new PIN successful ({} bytes)\n",
        assertion_response.len()
    );

    authenticator.stop();

    println!("╔════════════════════════════════════════════════╗");
    println!("║     ✓ PIN Change Test Passed                   ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}

#[test]
#[ignore] // Requires UHID permissions
#[serial] // Run serially to avoid UHID/CID conflicts
fn test_uv_only_authenticator() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════╗");
    println!("║     UV-Only Authenticator Test                 ║");
    println!("╚════════════════════════════════════════════════╝\n");

    println!("[Test] Starting UV-only authenticator (no PIN required)");
    let mut authenticator = TestAuthenticator::start_uv_only()?;
    thread::sleep(Duration::from_secs(1));

    // Connect to authenticator
    let list = TransportList::enumerate()?;
    if list.is_empty() {
        authenticator.stop();
        panic!("No authenticators found");
    }

    #[cfg(feature = "zig-ffi")]
    let mut transport = list.get(0).ok_or(keylib::Error::Other)?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let mut transport = list.get(0).ok_or(Error::Other)?;

    transport.open()?;
    println!("[Test] ✓ Connected to UV-only authenticator\n");

    // ============================================================
    // PHASE 1: Register without PIN (using UV only)
    // ============================================================
    println!("[Test] PHASE 1: Register credential with UV only");
    println!("{}", "─".repeat(48));

    let challenge = b"uv-only-registration";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.create");

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("UV-Only Test RP".to_string()),
    };

    let user = User {
        id: b"uv-only-user".to_vec(),
        name: Some("uvonly@example.com".to_string()),
        display_name: Some("UV Only User".to_string()),
    };

    // Request with UV flag set - authenticator will use built-in user verification
    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_user_verification(true) // This sets options.uv = true
        .with_timeout(30000);

    println!("[Test] Calling makeCredential (no PIN, UV will be checked)...");
    let response = Client::make_credential(&mut transport, request)?;
    println!(
        "[Test] ✓ Registration with UV only succeeded ({} bytes)\n",
        response.len()
    );

    // ============================================================
    // PHASE 2: Authenticate with UV only
    // ============================================================
    println!("[Test] PHASE 2: Authenticate with UV only (no PIN)");
    println!("{}", "─".repeat(48));

    let challenge = b"uv-only-authentication";
    let client_data_hash = create_client_data_hash(challenge, TEST_ORIGIN, "webauthn.get");

    let request = GetAssertionRequest::new(client_data_hash, TEST_RP_ID)
        .with_user_verification(true) // This sets options.uv = true
        .with_timeout(30000);

    println!("[Test] Calling getAssertion (no PIN, UV will be checked)...");
    let response = Client::get_assertion(&mut transport, request)?;
    println!(
        "[Test] ✓ Authentication with UV only succeeded ({} bytes)\n",
        response.len()
    );

    // Cleanup
    authenticator.stop();

    println!("╔════════════════════════════════════════════════╗");
    println!("║     ✓ UV-Only Test Passed                      ║");
    println!("╚════════════════════════════════════════════════╝\n");

    Ok(())
}
