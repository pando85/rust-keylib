//! Example: PIN Protocol Usage
//!
//! This example demonstrates how to use the PIN/UV authentication protocol
//! with a FIDO2 authenticator.
//!
//! **Requires**: `zig-ffi` feature (currently not compatible with `pure-rust`)
//!
//! # Prerequisites
//! - A FIDO2 authenticator connected via USB
//! - The authenticator must have a PIN configured
//!
//! # Usage
//! ```bash
//! cargo run --example pin_protocol
//! ```

use keylib::client::TransportList;
use keylib::client_pin::{PinProtocol, PinUvAuthEncapsulation};
use keylib::error::Result;

fn main() -> Result<()> {
    println!("PIN Protocol Example");
    println!("===================\n");

    // Enumerate available transports
    println!("Enumerating transports...");
    let list = match TransportList::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("Failed to enumerate transports: {:?}", e);
            eprintln!("\nNote: This example requires a FIDO2 authenticator connected via USB.");
            return Err(e);
        }
    };

    if list.is_empty() {
        eprintln!("No authenticators found. Please connect a FIDO2 device.");
        return Ok(());
    }

    println!("Found {} transport(s)", list.len());

    // Get the first transport
    let mut transport = match list.get(0) {
        Some(t) => t,
        None => {
            eprintln!("Failed to get transport");
            return Ok(());
        }
    };

    // Open the transport
    println!("Opening transport...");
    transport.open()?;
    println!("Transport opened successfully!\n");

    // Use PIN Protocol V2 (recommended for newer authenticators)
    let protocol = PinProtocol::V2;
    println!("Establishing key agreement with protocol {:?}...", protocol);

    // Create PIN encapsulation (performs ECDH key agreement)
    let mut encapsulation = match PinUvAuthEncapsulation::new(&mut transport, protocol) {
        Ok(enc) => {
            println!("Key agreement successful!");
            enc
        }
        Err(e) => {
            eprintln!("Failed to establish key agreement: {:?}", e);
            return Err(e);
        }
    };

    // Get platform public key (for debugging/verification)
    match encapsulation.get_platform_public_key() {
        Ok(key) => {
            println!(
                "Platform public key (first 16 bytes): {:02x?}...",
                &key[..16]
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not retrieve platform public key: {:?}", e);
        }
    }

    // Get PIN token (CTAP 2.0 style)
    println!("\nAttempting to get PIN token...");
    println!("Note: Replace '123456' with your actual authenticator PIN");

    let pin = "123456"; // Replace with actual PIN
    match encapsulation.get_pin_token(&mut transport, pin) {
        Ok(token) => {
            println!("PIN token retrieved successfully!");
            println!("Token length: {} bytes", token.len());
            println!(
                "Token (first 16 bytes): {:02x?}...",
                &token[..token.len().min(16)]
            );
        }
        Err(e) => {
            eprintln!("Failed to get PIN token: {:?}", e);
            eprintln!("This might be due to:");
            eprintln!("  - Incorrect PIN");
            eprintln!("  - No PIN configured on authenticator");
            eprintln!("  - Authenticator requires user presence");
        }
    }

    // Get PIN token with permissions (CTAP 2.1+ style)
    println!("\nAttempting to get PIN token with permissions...");

    // Permission bits:
    // mc=1 (makeCredential), ga=2 (getAssertion), cm=4 (credentialManagement)
    // be=8 (bioEnrollment), lbw=16 (largeBlobWrite), acfg=32 (authenticatorConfig)
    let permissions = 0x03; // mc + ga (make credential and get assertion)
    let rp_id = Some("example.com");

    match encapsulation.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        pin,
        permissions,
        rp_id,
    ) {
        Ok(token) => {
            println!("PIN/UV token with permissions retrieved successfully!");
            println!("Token length: {} bytes", token.len());
            println!(
                "Token (first 16 bytes): {:02x?}...",
                &token[..token.len().min(16)]
            );
            println!("Permissions: 0x{:02x}", permissions);
            if let Some(id) = rp_id {
                println!("Scoped to RP ID: {}", id);
            }
        }
        Err(e) => {
            eprintln!("Failed to get PIN token with permissions: {:?}", e);
            eprintln!("This might be because:");
            eprintln!("  - Authenticator doesn't support CTAP 2.1");
            eprintln!("  - Incorrect PIN");
            eprintln!("  - Invalid permissions or RP ID");
        }
    }

    println!("\nExample completed!");
    Ok(())
}
