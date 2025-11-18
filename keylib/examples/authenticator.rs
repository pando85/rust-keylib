//! Virtual FIDO2 Authenticator Example
//!
//! This example creates a virtual FIDO2 authenticator using UHID (Userspace HID).
//! It demonstrates how to:
//! - Set up an authenticator with callbacks
//! - Handle CTAP HID protocol
//! - Process CTAP commands
//! - Store credentials in memory
//!
//! # Prerequisites
//!
//! - Linux with UHID kernel module loaded (`sudo modprobe uhid`)
//! - Proper permissions to access /dev/uhid (user in `fido` group)
//! - Udev rules configured (see DEVELOPMENT.md)
//!
//! # Usage
//! ```bash
//! cargo run --example authenticator --features pure-rust
//! ```
//!
//! The authenticator will run until you press Ctrl+C.

use keylib::common::{Credential, CredentialRef, Result};
use keylib::rust_impl::authenticator::{
    Authenticator, AuthenticatorConfig, CallbacksBuilder, UpResult, UvResult,
};
use keylib::rust_impl::uhid::Uhid;
use keylib_transport::{Cmd, Message, Packet};

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const UHID_ERROR_MESSAGE: &str = "Make sure you have the uhid kernel module loaded and proper permissions.\n\
Run the following commands as root:\n\
  modprobe uhid\n\
  groupadd fido 2>/dev/null || true\n\
  usermod -a -G fido $USER\n\
  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' > /etc/udev/rules.d/90-uinput.rules\n\
  udevadm control --reload-rules && udevadm trigger";

// PIN configuration - "123456" hashed with SHA-256
fn get_pin_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"123456");
    hasher.finalize().into()
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════╗");
    println!("║     Virtual FIDO2 Authenticator                ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Create credential storage
    let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));

    // Setup PIN
    Authenticator::set_pin_hash(&get_pin_hash());
    println!("[Setup] PIN configured: 123456");

    // Setup callbacks
    let creds_write = credentials.clone();
    let creds_read = credentials.clone();
    let creds_get = credentials.clone();
    let creds_delete = credentials.clone();

    let callbacks = CallbacksBuilder::new()
        .up(Arc::new(|info, user, rp| {
            println!(
                "[Callback] User presence requested: {} (user: {:?}, rp: {:?})",
                info, user, rp
            );
            Ok(UpResult::Accepted)
        }))
        .uv(Arc::new(|info, user, rp| {
            println!(
                "[Callback] User verification requested: {} (user: {:?}, rp: {:?})",
                info, user, rp
            );
            Ok(UvResult::Accepted)
        }))
        .write(Arc::new(move |_id, _rp, cred: CredentialRef| {
            let mut store = creds_write.lock().unwrap();
            store.insert(cred.id.to_vec(), cred.to_owned());
            println!("[Callback] Stored credential for RP: {}", cred.rp_id);
            println!("           User: {:?}", cred.user_name);
            println!("           Total credentials: {}", store.len());
            Ok(())
        }))
        .read_credentials(Arc::new(move |rp_id, user_id| {
            let store = creds_read.lock().unwrap();
            let filtered: Vec<Credential> = store
                .values()
                .filter(|c| {
                    c.rp.id == rp_id && (user_id.is_none() || user_id == Some(c.user.id.as_slice()))
                })
                .cloned()
                .collect();
            println!(
                "[Callback] Read {} credentials for RP: {}",
                filtered.len(),
                rp_id
            );
            Ok(filtered)
        }))
        .get_credential(Arc::new(move |cred_id| {
            let store = creds_get.lock().unwrap();
            let result = store
                .get(cred_id)
                .cloned()
                .ok_or(keylib::common::Error::DoesNotExist);
            if result.is_ok() {
                println!(
                    "[Callback] Retrieved credential: {}",
                    hex::encode(&cred_id[..8.min(cred_id.len())])
                );
            }
            result
        }))
        .delete(Arc::new(move |cred_id| {
            let mut store = creds_delete.lock().unwrap();
            store.remove(cred_id.as_bytes());
            println!("[Callback] Deleted credential: {}", cred_id);
            println!("           Remaining credentials: {}", store.len());
            Ok(())
        }))
        .build();

    // Configure authenticator
    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
        .force_resident_keys(true)  // For testing: always store credentials
        .build();

    println!("[Setup] Creating authenticator...");
    let mut auth = Authenticator::with_config(callbacks, config)?;
    println!("[Setup] ✓ Authenticator created");

    // Open UHID device
    println!("[Setup] Opening UHID device...");
    let uhid = match Uhid::open() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("❌ Failed to open UHID device: {:?}", e);
            eprintln!();
            eprintln!("{}", UHID_ERROR_MESSAGE);
            return Err(e);
        }
    };
    println!("[Setup] ✓ UHID device opened");

    println!();
    println!("╔════════════════════════════════════════════════╗");
    println!("║  Authenticator Ready - Waiting for requests   ║");
    println!("╚════════════════════════════════════════════════╝");
    println!();
    println!("The virtual authenticator is now running.");
    println!("You can connect to it using USB HID transport.");
    println!("Press Ctrl+C to stop.");
    println!();

    // CTAP HID state
    let mut current_channel: u32 = 0xffffffff; // Broadcast channel
    let mut next_channel_id: u32 = 1; // Channel ID allocator (starts at 1)
    let mut pending_packets: Vec<Packet> = Vec::new();
    let mut response_buffer = Vec::new();
    let mut buffer = [0u8; 64];

    // Main loop
    loop {
        match uhid.read_packet(&mut buffer) {
            Ok(len) if len > 0 => {
                println!("[UHID] Received {} bytes", len);
                let packet = Packet::from_bytes(buffer);
                println!(
                    "[UHID] Packet: CID=0x{:08x}, Type={}, Payload={} bytes",
                    packet.cid(),
                    if packet.is_init() { "INIT" } else { "CONT" },
                    packet.payload().len()
                );

                // Debug: Show raw packet bytes
                if packet.is_init() && packet.payload().len() > 0 {
                    let cmd_byte = buffer[4]; // Command byte is at offset 4
                    println!("[UHID] Raw command byte in packet: 0x{:02x}", cmd_byte);
                    println!("[UHID]   INIT flag (0x80): {}", if cmd_byte & 0x80 != 0 { "set" } else { "clear" });
                    println!("[UHID]   Command (lower 7 bits): 0x{:02x}", cmd_byte & 0x7F);
                }

                // Handle initialization packets
                if packet.is_init() {
                    current_channel = packet.cid();
                    pending_packets.clear();
                    pending_packets.push(packet);

                    println!("[CTAP] New message on channel 0x{:08x}", current_channel);

                    // Check if this is a complete message
                    if let Some(payload_len) = pending_packets[0].payload_len() {
                        let init_data_len = pending_packets[0].payload().len();
                        println!(
                            "[CTAP] Single-packet message: {} bytes (expected {})",
                            init_data_len, payload_len
                        );
                        if init_data_len >= payload_len as usize {
                            let _ = process_message(
                                &mut auth,
                                &uhid,
                                &pending_packets,
                                &mut response_buffer,
                                &mut next_channel_id,
                            );
                            pending_packets.clear();
                        }
                    }
                } else {
                    // Continuation packet
                    if packet.cid() == current_channel {
                        pending_packets.push(packet);
                        println!(
                            "[CTAP] Continuation packet {} received",
                            pending_packets.len() - 1
                        );

                        // Check if we have the complete message
                        if let Some(first) = pending_packets.first() {
                            if let Some(total_len) = first.payload_len() {
                                let mut received_len = first.payload().len();
                                for pkt in &pending_packets[1..] {
                                    received_len += pkt.payload().len();
                                }

                                println!(
                                    "[CTAP] Multi-packet message: {}/{} bytes received",
                                    received_len, total_len
                                );

                                if received_len >= total_len as usize {
                                    let _ = process_message(
                                        &mut auth,
                                        &uhid,
                                        &pending_packets,
                                        &mut response_buffer,
                                        &mut next_channel_id,
                                    );
                                    pending_packets.clear();
                                }
                            }
                        }
                    } else {
                        println!(
                            "[CTAP] ⚠ Ignored packet for wrong channel: 0x{:08x} (expected 0x{:08x})",
                            packet.cid(),
                            current_channel
                        );
                    }
                }
            }
            Ok(_) => {
                // No data, sleep briefly
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                println!("[UHID] ⚠ Read error: {:?}", e);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Process a complete CTAP HID message
fn process_message(
    auth: &mut Authenticator,
    uhid: &Uhid,
    packets: &[Packet],
    response_buffer: &mut Vec<u8>,
    next_channel_id: &mut u32,
) -> Result<()> {
    println!("[CTAP] Processing message from {} packet(s)", packets.len());

    let message = Message::from_packets(packets).map_err(|e| {
        println!("[CTAP] ✗ Failed to parse message from packets: {:?}", e);
        keylib::common::Error::Other
    })?;

    let cid = message.cid;
    let cmd = message.cmd;

    println!(
        "[CTAP] Command: {:?}, CID: 0x{:08x}, Payload: {} bytes",
        cmd,
        cid,
        message.data.len()
    );

    // Debug: show raw command byte
    if !packets.is_empty() {
        let first_packet = &packets[0];
        let payload = first_packet.payload();
        if !payload.is_empty() {
            let cmd_byte = payload[0];
            println!("[CTAP] Raw command byte from packet: 0x{:02x}", cmd_byte);
        }
    }

    match cmd {
        Cmd::Cbor => {
            // CTAP CBOR command
            println!(
                "[CTAP] CBOR request: {}",
                hex::encode(&message.data[..message.data.len().min(32)])
            );

            // Decode CTAP command type
            if !message.data.is_empty() {
                let cmd_byte = message.data[0];
                let cmd_name = match cmd_byte {
                    0x01 => "authenticatorMakeCredential",
                    0x02 => "authenticatorGetAssertion",
                    0x04 => "authenticatorGetInfo",
                    0x06 => "authenticatorClientPIN",
                    0x07 => "authenticatorReset",
                    0x08 => "authenticatorGetNextAssertion",
                    0x0a => "authenticatorCredentialManagement",
                    0x0b => "authenticatorSelection",
                    _ => "unknown",
                };
                println!("[CTAP] Command type: 0x{:02x} ({})", cmd_byte, cmd_name);

                // For ClientPIN commands, decode the subcommand
                if cmd_byte == 0x06 && message.data.len() > 1 {
                    if let Ok(value) = ciborium::de::from_reader::<ciborium::value::Value, _>(&message.data[1..]) {
                        if let ciborium::value::Value::Map(map) = value {
                            for (k, v) in &map {
                                if let ciborium::value::Value::Integer(key_int) = k {
                                    let key_num: i128 = (*key_int).into();
                                    if key_num == 2 {
                                        if let ciborium::value::Value::Integer(subcmd) = v {
                                            let subcmd_num: i128 = (*subcmd).into();
                                            let subcmd_name = match subcmd_num {
                                                0x01 => "getPinRetries",
                                                0x02 => "getKeyAgreement",
                                                0x03 => "setPIN",
                                                0x04 => "changePIN",
                                                0x05 => "getPinToken (deprecated)",
                                                0x06 => "getPinUvAuthTokenUsingPin",
                                                0x07 => "getUVRetries",
                                                0x08 => "getPinUvAuthTokenUsingUv",
                                                0x09 => "getPinUvAuthTokenUsingPinWithPermissions",
                                                _ => "unknown",
                                            };
                                            println!("[CTAP] ClientPIN SubCommand: 0x{:02x} ({})", subcmd_num, subcmd_name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            response_buffer.clear();
            match auth.handle(&message.data, response_buffer) {
                Ok(_) => {
                    println!(
                        "[CTAP] ✓ Command processed ({} bytes response)",
                        response_buffer.len()
                    );
                    println!(
                        "[CTAP] CBOR response: {}",
                        hex::encode(&response_buffer[..response_buffer.len().min(32)])
                    );

                    // Decode response status
                    if !response_buffer.is_empty() {
                        let status = response_buffer[0];
                        if status == 0x00 {
                            println!("[CTAP] Response status: CTAP2_OK");
                        } else {
                            let error_name = match status {
                                0x01 => "CTAP1_ERR_INVALID_COMMAND",
                                0x02 => "CTAP1_ERR_INVALID_PARAMETER",
                                0x03 => "CTAP1_ERR_INVALID_LENGTH",
                                0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
                                0x12 => "CTAP2_ERR_MISSING_PARAMETER",
                                0x14 => "CTAP2_ERR_LIMIT_EXCEEDED",
                                0x15 => "CTAP2_ERR_UNSUPPORTED_EXTENSION",
                                0x16 => "CTAP2_ERR_CREDENTIAL_EXCLUDED",
                                0x21 => "CTAP2_ERR_OPERATION_DENIED",
                                0x22 => "CTAP2_ERR_KEY_STORE_FULL",
                                0x2D => "CTAP2_ERR_REQUEST_TOO_LARGE",
                                0x2E => "CTAP2_ERR_NO_CREDENTIALS",
                                0x31 => "CTAP2_ERR_PIN_INVALID",
                                0x32 => "CTAP2_ERR_PIN_BLOCKED",
                                0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
                                0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
                                0x35 => "CTAP2_ERR_PIN_NOT_SET",
                                0x36 => "CTAP2_ERR_PIN_REQUIRED",
                                0x37 => "CTAP2_ERR_PIN_POLICY_VIOLATION",
                                0x38 => "CTAP2_ERR_PIN_TOKEN_EXPIRED",
                                _ => "UNKNOWN_ERROR",
                            };
                            println!("[CTAP] Response status: {} (0x{:02x})", error_name, status);
                        }
                    }

                    let response_msg = Message::new(cid, Cmd::Cbor, response_buffer.clone());
                    send_message(uhid, &response_msg)?;
                }
                Err(e) => {
                    println!("[CTAP] ✗ Command failed: {:?}", e);
                    let response_msg = Message::new(cid, Cmd::Cbor, vec![0x01]);
                    send_message(uhid, &response_msg)?;
                }
            }
        }
        Cmd::Init => {
            // CTAP HID INIT - allocate a new channel ID
            if message.data.len() >= 8 {
                // Allocate new channel ID
                let allocated_cid = *next_channel_id;
                *next_channel_id += 1;

                let mut response_data = message.data[..8].to_vec(); // Echo nonce
                response_data.extend_from_slice(&allocated_cid.to_be_bytes()); // NEW channel ID
                response_data.push(2); // CTAP protocol version
                response_data.push(0); // Major device version
                response_data.push(0); // Minor device version
                response_data.push(0); // Build device version

                let capabilities = 0x04 | 0x08; // CBOR (0x04) + NMSG (0x08, no U2F)
                response_data.push(capabilities);

                println!(
                    "[CTAP] INIT command processed (allocated NEW CID: 0x{:08x})",
                    allocated_cid
                );
                println!("[CTAP] INIT response details:");
                println!("[CTAP]   Nonce: {}", hex::encode(&response_data[0..8]));
                println!("[CTAP]   New CID: 0x{:08x}", allocated_cid);
                println!("[CTAP]   Protocol version: {}", response_data[12]);
                println!("[CTAP]   Device version: {}.{}.{}", response_data[13], response_data[14], response_data[15]);
                println!("[CTAP]   Capabilities: 0x{:02x}", capabilities);
                println!("[CTAP]     - WINK: {}", if capabilities & 0x01 != 0 { "yes" } else { "no" });
                println!("[CTAP]     - CBOR: {}", if capabilities & 0x04 != 0 { "yes" } else { "no" });
                println!("[CTAP]     - NMSG: {}", if capabilities & 0x08 != 0 { "yes" } else { "no" });
                println!("[CTAP]   Total response: {} bytes: {}", response_data.len(), hex::encode(&response_data));
                // Respond on broadcast channel with new CID in payload
                let response_msg = Message::new(0xffffffff, Cmd::Init, response_data);
                send_message(uhid, &response_msg)?;
            } else {
                println!(
                    "[CTAP] ⚠ INIT command with invalid data length: {}",
                    message.data.len()
                );
            }
        }
        Cmd::Ping => {
            // Echo ping data
            println!(
                "[CTAP] PING command processed ({} bytes)",
                message.data.len()
            );
            let response_msg = Message::new(cid, Cmd::Ping, message.data);
            send_message(uhid, &response_msg)?;
        }
        _ => {
            println!("[CTAP] ⚠ Unknown command: {:?}", cmd);
        }
    }

    Ok(())
}

/// Send a CTAP HID message via UHID
fn send_message(uhid: &Uhid, message: &Message) -> Result<()> {
    let packets = message.to_packets().map_err(|e| {
        println!("[CTAP] ✗ Failed to create packets from message: {:?}", e);
        keylib::common::Error::Other
    })?;

    println!(
        "[CTAP] Sending response: {} packet(s), {} bytes total",
        packets.len(),
        message.data.len()
    );

    for (i, packet) in packets.iter().enumerate() {
        match uhid.write_packet(packet.as_bytes()) {
            Ok(_) => {
                println!("[UHID] ✓ Sent packet {}/{}", i + 1, packets.len());
            }
            Err(e) => {
                println!(
                    "[UHID] ✗ Failed to send packet {}/{}: {:?}",
                    i + 1,
                    packets.len(),
                    e
                );
                return Err(e);
            }
        }
    }

    Ok(())
}
