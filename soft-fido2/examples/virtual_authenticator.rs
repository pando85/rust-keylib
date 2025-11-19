//! Virtual FIDO2 Authenticator Example for Browser Testing
//!
//! This example creates a virtual FIDO2 authenticator using Linux UHID that
//! can be used with real web browsers for WebAuthn testing.
//!
//! # Usage
//!
//! 1. Ensure you have UHID permissions:
//!    ```bash
//!    sudo modprobe uhid
//!    sudo usermod -a -G fido $USER
//!    # Create udev rule:
//!    echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | sudo tee /etc/udev/rules.d/90-uhid.rules
//!    sudo udevadm control --reload-rules
//!    # Log out and back in for group membership to take effect
//!    ```
//!
//! 2. Run the authenticator:
//!    ```bash
//!    cargo run --example virtual_authenticator
//!    ```
//!
//! 3. Test with WebAuthn sites:
//!    - Open https://webauthn.firstyear.id.au/ (webauthn-rs demo)
//!    - Or try https://webauthn.io/
//!    - Or https://www.passwordless.dev/test
//!    - The virtual authenticator will appear as a USB security key
//!
//! 4. In your browser:
//!    - Click "Register" or "Create Credential"
//!    - Browser will detect the virtual authenticator
//!    - Authenticator will auto-approve (no user interaction needed)
//!    - Check console output to see what's happening
//!
//! # What This Does
//!
//! - Creates a UHID virtual HID device (appears as USB device to OS)
//! - Implements CTAP2 protocol (FIDO2)
//! - Stores credentials in memory
//! - Auto-approves all user presence/verification requests
//! - Supports discoverable credentials (resident keys)
//! - Works with any WebAuthn-enabled website
//!
//! # Features Demonstrated
//!
//! - Passkey registration and authentication
//! - Discoverable credentials (usernameless login)
//! - User verification (UV)
//! - Multiple credentials per RP
//! - Counter-based replay protection
//! - Extension support (credProtect, hmac-secret)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use soft_fido2::{
    Authenticator, AuthenticatorConfig, AuthenticatorOptions, CallbacksBuilder, Credential, Error,
    Result, UpResult, UvResult,
};
use soft_fido2_transport::{CommandHandler, UhidDevice};

/// Wrapper that implements CommandHandler for the high-level Authenticator
struct AuthenticatorHandler {
    authenticator: Mutex<Authenticator>,
}

impl AuthenticatorHandler {
    fn new(authenticator: Authenticator) -> Self {
        Self {
            authenticator: Mutex::new(authenticator),
        }
    }
}

impl CommandHandler for AuthenticatorHandler {
    fn handle_command(
        &mut self,
        cmd: soft_fido2_transport::Cmd,
        data: &[u8],
    ) -> soft_fido2_transport::Result<Vec<u8>> {
        // Only handle CBOR commands (CTAP2)
        if cmd != soft_fido2_transport::Cmd::Cbor {
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }

        let mut auth = self.authenticator.lock().map_err(|_| {
            soft_fido2_transport::Error::Other("Failed to lock authenticator".to_string())
        })?;

        let mut response = Vec::new();
        auth.handle(data, &mut response)
            .map_err(|_| soft_fido2_transport::Error::Other("Command failed".to_string()))?;

        Ok(response)
    }
}

/// UHID Virtual Authenticator Runner
///
/// Manages the complete stack: UHID I/O → CTAP HID protocol → Authenticator
struct UhidAuthenticator {
    device: UhidDevice,
    handler: soft_fido2_transport::CtapHidHandler<AuthenticatorHandler>,
}

impl UhidAuthenticator {
    fn new(authenticator: Authenticator) -> Result<Self> {
        let device = UhidDevice::create_fido_device().map_err(|_| Error::Other)?;

        let auth_handler = AuthenticatorHandler::new(authenticator);
        let handler = soft_fido2_transport::CtapHidHandler::new(auth_handler);

        Ok(Self { device, handler })
    }

    /// Process one HID packet (non-blocking)
    ///
    /// Returns Ok(true) if a packet was processed, Ok(false) if no packet available.
    fn process_one(&mut self) -> Result<bool> {
        let mut packet_data = [0u8; 64];

        // Try to read a packet (non-blocking)
        match self.device.read_packet(&mut packet_data) {
            Ok(Some(_len)) => {
                // Parse packet
                let packet = soft_fido2_transport::Packet::from_bytes(packet_data);

                // Process through CTAP HID handler
                let response_packets = self
                    .handler
                    .process_packet(packet)
                    .map_err(|_| Error::Other)?;

                // Write response packets
                for response_packet in response_packets {
                    self.device
                        .write_packet(response_packet.as_bytes())
                        .map_err(|_| Error::Other)?;
                }

                Ok(true)
            }
            Ok(None) => Ok(false), // No packet available
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Run the authenticator event loop
    fn run(&mut self) -> Result<()> {
        let mut request_count = 0u64;

        loop {
            match self.process_one() {
                Ok(true) => {
                    request_count += 1;
                }
                Ok(false) => {
                    // No packet available, sleep briefly
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(Error::Timeout) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("✗ Error processing packet: {:?}", e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            // Print stats every 100 requests
            if request_count > 0 && request_count.is_multiple_of(100) {
                eprintln!("  [Stats] Processed {} requests", request_count);
            }
        }
    }
}

fn main() -> Result<()> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  Virtual FIDO2 Authenticator (UHID)                      ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    // Create credential storage
    let credentials = Arc::new(Mutex::new(HashMap::<Vec<u8>, Credential>::new()));
    let creds_write = credentials.clone();
    let creds_read = credentials.clone();
    let creds_get = credentials.clone();
    let creds_delete = credentials.clone();

    // Setup callbacks with user-friendly logging
    let callbacks = CallbacksBuilder::new()
        .up(Arc::new(|info, user, rp| {
            println!("\n  [UP] 👆 User Presence Requested");
            println!("       Info: {}", info);
            if let Some(u) = user {
                println!("       User: {}", u);
            }
            if let Some(r) = rp {
                println!("       RP: {}", r);
            }
            println!("       ✓ AUTO-APPROVED");
            Ok(UpResult::Accepted)
        }))
        .uv(Arc::new(|info, user, rp| {
            println!("\n  [UV] 🔐 User Verification Requested");
            println!("       Info: {}", info);
            if let Some(u) = user {
                println!("       User: {}", u);
            }
            if let Some(r) = rp {
                println!("       RP: {}", r);
            }
            println!("       ✓ AUTO-APPROVED (biometric/PIN simulated)");
            Ok(UvResult::Accepted)
        }))
        .write(Arc::new(move |rp_id, user_name, cred| {
            let mut store = creds_write.lock().unwrap();
            store.insert(cred.id.to_vec(), cred.to_owned());

            println!("\n✓ CREDENTIAL REGISTERED");
            println!("  RP ID: {}", rp_id);
            if !user_name.is_empty() {
                println!("  User: {}", user_name);
            }
            println!("  User ID: {} bytes", cred.user_id.len());
            println!("  Credential ID: {} bytes", cred.id.len());
            println!("  Discoverable: {}", cred.discoverable);
            if let Some(cp) = cred.cred_protect {
                println!("  CredProtect: 0x{:02x}", cp);
            }
            println!("  Total credentials stored: {}\n", store.len());

            Ok(())
        }))
        .read_credentials(Arc::new(move |rp_id, user_id| {
            let store = creds_read.lock().unwrap();
            let filtered: Vec<Credential> = store
                .values()
                .filter(|c| {
                    if c.rp.id != rp_id {
                        return false;
                    }
                    if let Some(uid) = user_id {
                        c.user.id == uid
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();

            println!(
                "  [READ] Found {} credential(s) for RP: {}",
                filtered.len(),
                rp_id
            );
            Ok(filtered)
        }))
        .get_credential(Arc::new(move |cred_id| {
            let store = creds_get.lock().unwrap();
            match store.get(cred_id) {
                Some(cred) => {
                    println!("\n  [AUTH] 🔑 Credential Retrieved");
                    println!("         RP: {}", cred.rp.id);
                    if let Some(ref name) = cred.user.name {
                        println!("         User: {}", name);
                    }
                    println!("         Sign count: {}", cred.sign_count);
                    Ok(cred.clone())
                }
                None => {
                    println!("\n  [AUTH] ✗ Credential not found");
                    Err(Error::DoesNotExist)
                }
            }
        }))
        .delete(Arc::new(move |cred_id| {
            let mut store = creds_delete.lock().unwrap();
            store.remove(cred_id.as_bytes());
            println!("  [DELETE] Credential removed\n");
            Ok(())
        }))
        .build();

    // Configure authenticator with full FIDO2 capabilities
    let config = AuthenticatorConfig::builder()
        .aaguid([
            // Custom AAGUID for soft-fido2
            0x73, 0x6f, 0x66, 0x74, 0x2d, 0x66, 0x69, 0x64, 0x6f, 0x32, 0x2d, 0x76, 0x69, 0x72,
            0x74, 0x75,
        ])
        .max_credentials(100)
        // Note: Default algorithm is ES256 (-7), which is the only one currently implemented
        .extensions(vec![
            "credProtect".to_string(),
            "hmac-secret".to_string(),
            "largeBlobKey".to_string(),
        ])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true) // Support discoverable credentials
                .with_user_presence(true) // Support UP
                .with_user_verification(Some(true)) // Support UV capability
                .with_client_pin(Some(true)), // Report PIN as set so browser requests UV
        )
        .build();

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  Authenticator Configuration                              ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  AAGUID: soft-fido2-virtu");
    println!("  Algorithms: ES256 (-7)");
    println!("  Resident Keys (rk): ✓ Supported");
    println!("  User Presence (up): ✓ Supported (auto-approved)");
    println!("  User Verification (uv): ✓ Supported (auto-approved)");
    println!("  Client PIN: Reported as SET (virtual - UV auto-approved)");
    println!("  Extensions: credProtect, hmac-secret, largeBlobKey");
    println!("  Max Credentials: 100");
    println!();

    // Create authenticator
    // Note: clientPin=true is set via options config, which tells browsers we support UV
    // We auto-approve all UV requests in callbacks (no actual PIN verification)
    let auth = Authenticator::with_config(callbacks, config)?;

    // Create UHID virtual device
    println!("Creating UHID virtual device...");
    let mut uhid_auth = UhidAuthenticator::new(auth).map_err(|e| {
        eprintln!("\n✗ Failed to create UHID device: {:?}", e);
        eprintln!("\nTroubleshooting:");
        eprintln!("  1. Check UHID module: sudo modprobe uhid");
        eprintln!("  2. Check permissions: groups | grep fido");
        eprintln!("  3. Check udev rules: cat /etc/udev/rules.d/90-uhid.rules");
        eprintln!("  4. Log out and back in if you just added the group");
        eprintln!();
        e
    })?;

    println!("✓ UHID device created successfully!\n");
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  Authenticator Ready - Waiting for WebAuthn requests...  ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    println!("Test with:");
    println!("  • https://webauthn.firstyear.id.au/ (webauthn-rs demo)");
    println!("  • https://webauthn.io/");
    println!("  • https://www.passwordless.dev/test");
    println!();
    println!("Press Ctrl+C to stop\n");

    // Run event loop
    uhid_auth.run()
}
