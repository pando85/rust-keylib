//! Unified End-to-End WebAuthn Flow Tests
//!
//! This test file works with BOTH zig-ffi and pure-rust implementations,
//! validating that pure-rust is a drop-in replacement for zig-ffi.
//!
//! # Prerequisites
//!
//! These tests require:
//! - Linux with UHID kernel module loaded (`sudo modprobe uhid`)
//! - Proper permissions to access /dev/uhid (user in `fido` group)
//!
//! # Running Tests
//!
//! With zig-ffi:
//! ```bash
//! cargo test --test e2e_unified_test --features bundled -- --ignored
//! ```
//!
//! With pure-rust:
//! ```bash
//! cargo test --test e2e_unified_test --features pure-rust --no-default-features -- --ignored
//! ```
//!
//! # Test Flow
//!
//! 1. Start a virtual authenticator in a background thread
//! 2. Use the Client API to perform registration (makeCredential)
//! 3. Use the Client API to perform authentication (getAssertion)
//! 4. Verify the complete flow succeeds

#![cfg(any(feature = "zig-ffi", feature = "pure-rust"))]

// Feature-specific imports for zig-ffi
#[cfg(feature = "zig-ffi")]
use keylib::{
    Authenticator, AuthenticatorConfig, AuthenticatorOptions, Callbacks, Credential, CredentialRef,
    CtapCommand, Error, Result, UpResult, UvResult,
};

#[cfg(feature = "zig-ffi")]
use keylib::client::{
    ClientDataHash, GetAssertionRequest, MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
    TransportList, User,
};

#[cfg(feature = "zig-ffi")]
use keylib::credential::RelyingParty;

// Feature-specific imports for pure-rust
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
use keylib::{
    Authenticator, AuthenticatorConfig, ClientDataHash, Credential, CredentialRef, Error,
    GetAssertionRequest, MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol, RelyingParty,
    Result, UpResult, User, UvResult,
};

#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
use keylib::rust_impl::{
    authenticator_options::AuthenticatorOptions, callbacks::Callbacks,
    ctap_command::CtapCommand, transport::TransportList,
};

// CTAP HID layer - conditional imports
#[cfg(feature = "zig-ffi")]
use keylib::ctaphid::Ctaphid;

#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
use keylib_transport::{Cmd, Message, Packet};

// Common imports
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

    // Build callbacks using unified API (zig-ffi compatible)
    let credentials_clone = credentials.clone();
    let write_callback = Arc::new(
        move |id: &str, rp: &str, cred: CredentialRef| -> Result<()> {
            let mut store = credentials_clone.lock().unwrap();
            let key = id.as_bytes().to_vec();
            store.insert(key, cred.to_owned());
            println!("[Authenticator] Stored credential for RP: {}", rp);
            Ok(())
        },
    );

    let credentials_clone = credentials.clone();
    let read_callback = Arc::new(move |id: &str, _rp: &str| -> Result<Vec<u8>> {
        let store = credentials_clone.lock().unwrap();
        let key = id.as_bytes().to_vec();
        if let Some(cred) = store.get(&key) {
            return cred.to_bytes();
        }
        Err(Error::DoesNotExist)
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
        move |id: Option<&str>, rp: Option<&str>, _hash: Option<[u8; 32]>| -> Result<Credential> {
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

            Err(Error::DoesNotExist)
        },
    );

    let read_next_callback = Arc::new(|| -> Result<Credential> {
        // For simplicity, we don't support iteration in tests
        Err(Error::DoesNotExist)
    });

    // Build callbacks using unified constructor
    let callbacks = Callbacks::new(
        Some(up_callback),
        Some(uv_callback),
        None, // select
        Some(read_callback),
        Some(write_callback),
        Some(delete_callback),
        Some(read_first_callback),
        Some(read_next_callback),
    );

    // Configure authenticator
    let options = AuthenticatorOptions::new()
        .with_resident_keys(true)
        .with_user_presence(true)
        .with_user_verification(Some(true))
        .with_client_pin(Some(use_pin))
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

    // Create authenticator with configuration
    let mut auth = Authenticator::with_config(callbacks, config)?;

    // Open UHID device
    #[cfg(feature = "zig-ffi")]
    let uhid = keylib::uhid::Uhid::open().map_err(|_| {
        eprintln!("Failed to open UHID device.");
        eprintln!("Make sure you have the uhid kernel module loaded and proper permissions.");
        Error::Other
    })?;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    let uhid = keylib::rust_impl::uhid::Uhid::open().map_err(|_| {
        eprintln!("Failed to open UHID device.");
        eprintln!("Make sure you have the uhid kernel module loaded and proper permissions.");
        Error::Other
    })?;

    // CTAP HID layer - implementation specific
    #[cfg(feature = "zig-ffi")]
    {
        run_authenticator_loop_zig_ffi(&mut auth, &uhid, stop_flag)
    }

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    {
        run_authenticator_loop_pure_rust(&mut auth, &uhid, stop_flag)
    }
}

/// Authenticator loop for zig-ffi (uses Ctaphid)
#[cfg(feature = "zig-ffi")]
fn run_authenticator_loop_zig_ffi(
    auth: &mut Authenticator,
    uhid: &keylib::uhid::Uhid,
    stop_flag: Arc<Mutex<bool>>,
) -> Result<()> {
    let mut ctaphid = Ctaphid::new()?;
    let mut response_buffer = Vec::new();

    println!("[Authenticator] Started and ready (zig-ffi)");

    let mut buffer = [0u8; 64];
    loop {
        if let Ok(flag) = stop_flag.lock()
            && *flag
        {
            println!("[Authenticator] Stopping");
            break;
        }

        match uhid.read_packet(&mut buffer) {
            Ok(len) if len > 0 => {
                if let Some(mut response) = ctaphid.handle(&buffer) {
                    match response.command() {
                        keylib::ctaphid::Cmd::Cbor => {
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

                    for packet in response.packets() {
                        if let Err(e) = uhid.write_packet(&packet) {
                            eprintln!("[Authenticator] Failed to write response: {:?}", e);
                        }
                    }
                }
            }
            Ok(_) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

/// Authenticator loop for pure-rust (uses Message/Packet)
#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
fn run_authenticator_loop_pure_rust(
    auth: &mut Authenticator,
    uhid: &keylib::rust_impl::uhid::Uhid,
    stop_flag: Arc<Mutex<bool>>,
) -> Result<()> {
    println!("[Authenticator] Started and ready (pure-rust)");

    let mut current_channel: u32 = 0xffffffff;
    let mut pending_packets: Vec<Packet> = Vec::new();
    let mut buffer = [0u8; 64];

    loop {
        if *stop_flag.lock().unwrap() {
            println!("[Authenticator] Stopping");
            break;
        }

        match uhid.read_packet(&mut buffer) {
            Ok(len) if len > 0 => {
                let packet = Packet::from_bytes(buffer);

                if packet.is_init() {
                    current_channel = packet.cid();
                    pending_packets.clear();
                    pending_packets.push(packet);

                    if let Some(payload_len) = pending_packets[0].payload_len() {
                        let init_data_len = pending_packets[0].payload().len();
                        if init_data_len >= payload_len as usize {
                            process_message_pure_rust(auth, uhid, &pending_packets)?;
                            pending_packets.clear();
                        }
                    }
                } else {
                    if packet.cid() == current_channel {
                        pending_packets.push(packet);

                        if let Some(first) = pending_packets.first() {
                            if let Some(total_len) = first.payload_len() {
                                let mut received_len = first.payload().len();
                                for pkt in &pending_packets[1..] {
                                    received_len += pkt.payload().len();
                                }

                                if received_len >= total_len as usize {
                                    process_message_pure_rust(auth, uhid, &pending_packets)?;
                                    pending_packets.clear();
                                }
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("[Authenticator] Read error: {:?}", e);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
fn process_message_pure_rust(
    auth: &mut Authenticator,
    uhid: &keylib::rust_impl::uhid::Uhid,
    packets: &[Packet],
) -> Result<()> {
    let message = Message::from_packets(packets).map_err(|_| Error::Other)?;
    let cid = message.cid;
    let cmd = message.cmd;

    match cmd {
        Cmd::Cbor => {
            let mut response_buffer = Vec::new();
            match auth.handle(&message.data, &mut response_buffer) {
                Ok(_) => {
                    let response_msg = Message::new(cid, Cmd::Cbor, response_buffer);
                    send_message_pure_rust(uhid, &response_msg)?;
                }
                Err(e) => {
                    eprintln!("[Authenticator] Command error: {:?}", e);
                    let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01]);
                    send_message_pure_rust(uhid, &response_msg)?;
                }
            }
        }
        Cmd::Init => {
            if message.data.len() >= 8 {
                let mut response_data = message.data[..8].to_vec();
                response_data.extend_from_slice(&cid.to_be_bytes());
                response_data.push(2);
                response_data.push(0);
                response_data.push(0);
                response_data.push(0);
                response_data.push(0x01);

                let response_msg = Message::new(cid, Cmd::Init, response_data);
                send_message_pure_rust(uhid, &response_msg)?;
            }
        }
        Cmd::Ping => {
            let response_msg = Message::new(cid, Cmd::Ping, message.data);
            send_message_pure_rust(uhid, &response_msg)?;
        }
        _ => {
            eprintln!("[Authenticator] Unsupported command: {:?}", cmd);
        }
    }

    Ok(())
}

#[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
fn send_message_pure_rust(
    uhid: &keylib::rust_impl::uhid::Uhid,
    message: &Message,
) -> Result<()> {
    let packets = message.to_packets().map_err(|_| Error::Other)?;
    for packet in &packets {
        uhid.write_packet(packet.as_bytes())?;
    }
    Ok(())
}

/// Helper to create a ClientDataHash from a challenge
fn create_client_data_hash(challenge: &[u8], origin: &str, ceremony_type: &str) -> ClientDataHash {
    let client_data = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
        ceremony_type,
        BASE64_STANDARD.encode(challenge),
        origin
    );

    let hash_bytes = Sha256::digest(client_data.as_bytes());
    ClientDataHash::from_slice(&hash_bytes).expect("Valid 32-byte hash")
}

#[test]
#[ignore] // Requires UHID permissions
#[serial] // Run serially to avoid UHID/CID conflicts
fn test_unified_webauthn_flow() -> Result<()> {
    #[cfg(feature = "zig-ffi")]
    println!("\n╔════════════════════════════════════════════════╗");
    #[cfg(feature = "zig-ffi")]
    println!("║     E2E WebAuthn Flow Test (zig-ffi)          ║");
    #[cfg(feature = "zig-ffi")]
    println!("╚════════════════════════════════════════════════╝\n");

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    println!("\n╔════════════════════════════════════════════════╗");
    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    println!("║     E2E WebAuthn Flow Test (pure-rust)        ║");
    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    println!("╚════════════════════════════════════════════════╝\n");

    // Start virtual authenticator
    println!("[Test] Starting virtual authenticator...");
    let mut authenticator = TestAuthenticator::start()?;
    thread::sleep(Duration::from_secs(1));

    // Connect to authenticator
    println!("[Test] Connecting to authenticator...");
    let list = TransportList::enumerate()?;

    if list.is_empty() {
        authenticator.stop();
        panic!("No authenticators found - virtual authenticator may not have started");
    }

    let mut transport = list.get(0).ok_or(Error::Other)?;
    transport.open()?;
    println!("[Test] ✓ Connected to authenticator\n");

    // ============================================================
    // PHASE 1: REGISTRATION (makeCredential)
    // ============================================================
    println!("[Test] PHASE 1: Registration");
    println!("{}", "─".repeat(48));

    // Establish PIN protocol
    #[cfg(feature = "zig-ffi")]
    use keylib::client_pin::{PinProtocol, PinUvAuthEncapsulation};

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    use keylib::rust_impl::client_pin::{PinProtocol, PinUvAuthEncapsulation};

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

    #[cfg(feature = "zig-ffi")]
    use keylib::client::Client;

    #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
    use keylib::rust_impl::client::Client;

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

    // Calculate pinUvAuthParam
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
