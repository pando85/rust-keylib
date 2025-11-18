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

    match cmd {
        Cmd::Cbor => {
            // CTAP CBOR command
            println!(
                "[CTAP] CBOR request: {}",
                hex::encode(&message.data[..message.data.len().min(32)])
            );
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
                response_data.push(0x01); // Capabilities: CBOR

                println!(
                    "[CTAP] INIT command processed (allocated NEW CID: 0x{:08x})",
                    allocated_cid
                );
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
