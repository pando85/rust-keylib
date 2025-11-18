//! End-to-End WebAuthn Flow Tests for Pure Rust Implementation
//!
//! These tests simulate a complete WebAuthn registration and authentication flow
//! using the pure Rust CTAP implementation with a virtual authenticator and UHID transport.
//!
//! # Prerequisites
//!
//! These tests require:
//! - Linux with UHID kernel module loaded (`sudo modprobe uhid`)
//! - Proper permissions to access /dev/uhid (user in `fido` group)
//! - Run with: `cargo test --test e2e_pure_rust_test -- --ignored`
//!
//! # Test Flow
//!
//! 1. Start a virtual authenticator in a background thread
//! 2. Use the Client API to perform registration (makeCredential)
//! 3. Use the Client API to perform authentication (getAssertion)
//! 4. Verify the complete flow succeeds

// Only compile with pure-rust feature
#![cfg(feature = "pure-rust")]

use keylib::common::{
    ClientDataHash, Credential, CredentialRef, MakeCredentialRequest,
    PinUvAuth, PinUvAuthProtocol, RelyingParty, Result, User,
};
use keylib::rust_impl::authenticator::{
    Authenticator, AuthenticatorConfig, Callbacks, CallbacksBuilder, UpResult, UvResult,
};
use keylib::rust_impl::client::Client;
use keylib::rust_impl::client_pin::{PinProtocol, PinUvAuthEncapsulation};
use keylib::rust_impl::transport::TransportList;
use keylib::rust_impl::uhid::Uhid;

use keylib_transport::{Cmd, Message, Packet};

use serial_test::serial;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Test constants
const TEST_PIN: &str = "123456";
const TEST_RP_ID: &str = "test.example.com";
const TEST_USER_ID: &[u8] = b"test-user-123";
const TEST_USER_NAME: &str = "testuser@example.com";
const TEST_USER_DISPLAY_NAME: &str = "Test User";

/// Helper struct to manage the virtual authenticator lifecycle
struct TestAuthenticator {
    handle: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<Mutex<bool>>,
}

impl TestAuthenticator {
    /// Start a virtual authenticator in a background thread
    fn start() -> Result<Self> {
        let stop_flag = Arc::new(Mutex::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        // Credential storage
        let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));

        // Build callbacks
        let creds_write = Arc::clone(&credentials);
        let creds_read = Arc::clone(&credentials);
        let creds_get = Arc::clone(&credentials);
        let creds_delete = Arc::clone(&credentials);

        let callbacks = CallbacksBuilder::new()
            .up(Arc::new(|_, _, _| Ok(UpResult::Accepted)))
            .uv(Arc::new(|_, _, _| Ok(UvResult::Accepted)))
            .write(Arc::new(move |_id: &str, _rp_id: &str, cred: CredentialRef| {
                let mut store = creds_write.lock().unwrap();
                store.insert(cred.id.to_vec(), cred.to_owned());
                Ok(())
            }))
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
                    .ok_or(keylib::common::Error::DoesNotExist)
            }))
            .delete(Arc::new(move |cred_id: &str| {
                let mut store = creds_delete.lock().unwrap();
                store.remove(cred_id.as_bytes());
                Ok(())
            }))
            .build();

        // Configure authenticator
        let config = AuthenticatorConfig::builder()
            .aaguid([
                0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
                0x7c, 0x88,
            ])
            .max_credentials(25)
            .extensions(vec!["credProtect".to_string()])
            .build();

        // Set PIN hash
        let mut hasher = Sha256::new();
        hasher.update(TEST_PIN.as_bytes());
        let pin_hash: [u8; 32] = hasher.finalize().into();
        Authenticator::set_pin_hash(&pin_hash);

        // Spawn authenticator thread
        let handle = thread::spawn(move || {
            if let Err(e) = Self::run_authenticator(stop_flag_clone, callbacks, config) {
                eprintln!("[Authenticator] Error: {:?}", e);
            }
        });

        // Wait for authenticator to start
        thread::sleep(Duration::from_millis(100));

        Ok(Self {
            handle: Some(handle),
            stop_flag,
        })
    }

    /// Run the authenticator loop
    fn run_authenticator(
        stop_flag: Arc<Mutex<bool>>,
        callbacks: Callbacks,
        config: AuthenticatorConfig,
    ) -> Result<()> {
        // Create authenticator
        let mut auth = Authenticator::with_config(callbacks, config)?;

        // Open UHID device
        let uhid = Uhid::open().map_err(|e| {
            eprintln!("Failed to open UHID device: {:?}", e);
            eprintln!("Make sure UHID kernel module is loaded and you have permissions.");
            e
        })?;

        println!("[Authenticator] Started and ready");

        // CTAP HID state
        let mut current_channel: u32 = 0xffffffff; // Broadcast channel
        let mut pending_packets: Vec<Packet> = Vec::new();

        // Main authenticator loop
        let mut buffer = [0u8; 64];
        loop {
            // Check stop flag
            if *stop_flag.lock().unwrap() {
                println!("[Authenticator] Stopping");
                break;
            }

            // Read packet with timeout (non-blocking via spin loop in uhid.rs)
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
                                if let Err(e) =
                                    Self::process_message(&mut auth, &uhid, &pending_packets)
                                {
                                    eprintln!("[Authenticator] Error processing message: {:?}", e);
                                }
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
                                        if let Err(e) = Self::process_message(
                                            &mut auth,
                                            &uhid,
                                            &pending_packets,
                                        ) {
                                            eprintln!(
                                                "[Authenticator] Error processing message: {:?}",
                                                e
                                            );
                                        }
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
                Err(e) => {
                    eprintln!("[Authenticator] Read error: {:?}", e);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        Ok(())
    }

    /// Process a complete CTAP HID message
    fn process_message(
        auth: &mut Authenticator,
        uhid: &Uhid,
        packets: &[Packet],
    ) -> Result<()> {
        // Reassemble message
        let message = Message::from_packets(packets).map_err(|e| {
            eprintln!("[Authenticator] Failed to reassemble message: {:?}", e);
            keylib::common::Error::Other
        })?;

        let cid = message.cid;
        let cmd = message.cmd;

        // Handle CTAP commands
        match cmd {
            Cmd::Cbor => {
                // CTAP CBOR command - process through authenticator
                let mut response_buffer = Vec::new();
                match auth.handle(&message.data, &mut response_buffer) {
                    Ok(_) => {
                        // Send success response
                        let response_msg = Message::new(cid, Cmd::Cbor, response_buffer);
                        Self::send_message(uhid, &response_msg)?;
                    }
                    Err(e) => {
                        eprintln!("[Authenticator] Command error: {:?}", e);
                        // Send error response
                        let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01]); // CTAP2_ERR_INVALID_CBOR
                        Self::send_message(uhid, &response_msg)?;
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
                    Self::send_message(uhid, &response_msg)?;
                }
            }
            Cmd::Ping => {
                // Echo ping data
                let response_msg = Message::new(cid, Cmd::Ping, message.data);
                Self::send_message(uhid, &response_msg)?;
            }
            _ => {
                eprintln!("[Authenticator] Unsupported command: {:?}", cmd);
            }
        }

        Ok(())
    }

    /// Send a CTAP HID message via UHID
    fn send_message(uhid: &Uhid, message: &Message) -> Result<()> {
        let packets = message.to_packets().map_err(|e| {
            eprintln!("[Authenticator] Failed to create packets: {:?}", e);
            keylib::common::Error::Other
        })?;

        for packet in &packets {
            uhid.write_packet(packet.as_bytes())?;
        }

        Ok(())
    }

    /// Stop the authenticator and wait for the thread to finish
    fn stop(mut self) {
        *self.stop_flag.lock().unwrap() = true;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TestAuthenticator {
    fn drop(&mut self) {
        *self.stop_flag.lock().unwrap() = true;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Helper to create client data hash from challenge
fn create_client_data_hash(challenge: &[u8]) -> ClientDataHash {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let hash: [u8; 32] = hasher.finalize().into();
    ClientDataHash::new(hash)
}

#[test]
#[ignore] // Requires UHID permissions
#[serial]
fn test_pure_rust_make_credential_with_pin() {
    println!("\n[TEST] Testing MakeCredential with PIN (Pure Rust)");

    // Start virtual authenticator
    let auth = TestAuthenticator::start().expect("Failed to start authenticator");

    // Wait for kernel to register the UHID device as a HID device
    println!("[TEST] Waiting for UHID device to be registered by kernel...");
    thread::sleep(Duration::from_secs(2));

    // Enumerate transports
    println!("[TEST] Enumerating transports...");
    let list = TransportList::enumerate().expect("Failed to enumerate transports");

    if list.is_empty() {
        panic!("No transports found - ensure USB feature is enabled and UHID device is registered");
    }

    println!("[TEST] Found {} transport(s)", list.len());
    let mut transport = list.get(0).expect("Failed to get transport");
    transport.open().expect("Failed to open transport");

    println!("[OK] Transport opened");

    // Perform PIN protocol
    let mut pin_encap = PinUvAuthEncapsulation::new(&mut transport, PinProtocol::V2)
        .expect("Failed to create PIN encapsulation");

    println!("[OK] PIN key agreement complete");

    // Get PIN token with makeCredential permission (0x01)
    let pin_token = pin_encap
        .get_pin_uv_auth_token_using_pin_with_permissions(
            &mut transport,
            TEST_PIN,
            0x01, // makeCredential permission
            Some(TEST_RP_ID),
        )
        .expect("Failed to get PIN token");

    println!("[OK] PIN token obtained");

    // Create makeCredential request
    let challenge = b"test-challenge-12345678";
    let client_data_hash = create_client_data_hash(challenge);

    let rp = RelyingParty {
        id: TEST_RP_ID.to_string(),
        name: Some("Test RP".to_string()),
    };

    let user = User {
        id: TEST_USER_ID.to_vec(),
        name: Some(TEST_USER_NAME.to_string()),
        display_name: Some(TEST_USER_DISPLAY_NAME.to_string()),
    };

    // Calculate pinUvAuthParam
    let mut auth_data = client_data_hash.as_slice().to_vec();
    let rp_id_hash = {
        let mut hasher = Sha256::new();
        hasher.update(TEST_RP_ID.as_bytes());
        hasher.finalize().to_vec()
    };
    auth_data.extend_from_slice(&rp_id_hash);

    let pin_uv_auth_param = pin_encap
        .authenticate(&auth_data, &pin_token)
        .expect("Failed to create pinUvAuthParam");

    let pin_uv_auth = PinUvAuth::new(pin_uv_auth_param, PinUvAuthProtocol::V2);

    let request = MakeCredentialRequest::new(client_data_hash, rp, user)
        .with_resident_key(true)
        .with_user_verification(true)
        .with_pin_uv_auth(pin_uv_auth);

    println!("[INFO] Sending makeCredential request");

    // Send makeCredential
    let response = Client::make_credential(&mut transport, request)
        .expect("Failed to make credential");

    println!("[OK] Credential created, response: {} bytes", response.len());

    // Stop authenticator
    auth.stop();
    println!("[OK] Test complete");
}

#[test]
#[ignore] // Requires UHID permissions
#[serial]
fn test_pure_rust_authenticator_get_info() {
    println!("\n[TEST] Testing AuthenticatorGetInfo (Pure Rust)");

    let auth = TestAuthenticator::start().expect("Failed to start authenticator");

    // Wait for kernel to register the UHID device as a HID device
    // This can take a moment as the kernel needs to process the device
    println!("[TEST] Waiting for UHID device to be registered by kernel...");
    thread::sleep(Duration::from_secs(2));

    println!("[TEST] Enumerating transports...");
    let list = TransportList::enumerate().expect("Failed to enumerate transports");

    if list.is_empty() {
        panic!("No transports found - ensure USB feature is enabled and UHID device is registered");
    }

    println!("[TEST] Found {} transport(s)", list.len());
    let mut transport = list.get(0).expect("Failed to get transport");
    transport.open().expect("Failed to open transport");

    println!("[INFO] Sending getInfo request");

    let response = Client::authenticator_get_info(&mut transport)
        .expect("Failed to get authenticator info");

    println!("[OK] Got info: {} bytes", response.len());

    auth.stop();
    println!("[OK] Test complete");
}
