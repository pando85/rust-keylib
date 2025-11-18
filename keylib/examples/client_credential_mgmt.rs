//! Client-side example for testing Credential Management (0x0a)
//!
//! This example connects to a FIDO2 authenticator and tests:
//! - 0x0a/0x01: getCredsMetadata - Get credential counts
//! - 0x0a/0x02: enumerateRPsBegin - List relying parties
//!
//! **Requires**: `zig-ffi` feature (currently not compatible with `pure-rust`)
//!
//! Prerequisites:
//! - FIDO2 authenticator connected (e.g., passless running)
//! - PIN set to "123456" on the authenticator
//! - Some credentials stored (optional for testing enumeration)
//!
//! Run with:
//! ```bash
//! cargo run --example client_credential_mgmt
//! ```

use keylib::client::TransportList;
use keylib::credential_management::CredentialManagement;
use keylib::error::{KeylibError, Result};

fn main() -> Result<()> {
    println!("===============================================================");
    println!("  CTAP2 Credential Management Test Client");
    println!("===============================================================");
    println!();

    // Step 1: Connect to authenticator
    println!(">> STEP 1: Connecting to authenticator...");
    let transport_list = TransportList::enumerate()?;
    println!("  Found {} transport(s)", transport_list.len());

    if transport_list.is_empty() {
        println!();
        println!("[ERROR] No transports found!");
        println!();
        println!("  Make sure:");
        println!("  - Your FIDO2 authenticator is connected");
        println!("  - You have proper permissions (udev rules on Linux)");
        println!("  - The authenticator is not in use");
        println!();
        return Ok(());
    }

    let mut transport = transport_list.get(0).ok_or(KeylibError::Other)?;

    match transport.open() {
        Ok(_) => println!("  [OK] Transport opened"),
        Err(e) => {
            println!("  [ERROR] Failed to open transport: {:?}", e);
            println!();
            println!("  This usually means:");
            println!("  - Another process is using the authenticator");
            println!("  - Permission denied");
            println!();
            return Err(e);
        }
    }
    println!();

    // Step 2: Authenticate with PIN
    println!(">> STEP 2: Authenticating with PIN");
    println!("  Using PIN: 123456");
    println!();

    let pin = "123456";
    let protocol = 2;

    print!("  Getting PIN token... ");
    let mut client_pin = keylib::client_pin::PinUvAuthEncapsulation::new(
        &mut transport,
        keylib::client_pin::PinProtocol::V2,
    )?;
    let pin_token = match client_pin.get_pin_uv_auth_token_using_pin_with_permissions(
        &mut transport,
        pin,
        0x02, // credMgmt permission
        None, // no RP ID required
    ) {
        Ok(token) => {
            println!("SUCCESS!");
            println!("  [OK] PIN token obtained (permission: 0x02 = credMgmt)");
            token
        }
        Err(e) => {
            println!("FAILED");
            println!();
            println!("  [ERROR] {:?}", e);
            println!();
            println!("  Make sure:");
            println!("  - PIN is set to '123456' on your authenticator");
            println!("  - Authenticator supports PIN protocol");
            println!();
            return Err(e);
        }
    };
    println!();

    // Step 3: Set up credential management
    println!(">> STEP 3: Initializing credential management...");
    let mut cm = CredentialManagement::new(&mut transport);
    println!("  [OK] Credential management initialized");
    println!(); // Execute credential management commands
    println!("===============================================================");
    println!("  EXECUTING CREDENTIAL MANAGEMENT COMMANDS");
    println!("===============================================================");
    println!();

    // Command 1: Get metadata
    println!(">> COMMAND 0x0a/0x01: getCredsMetadata");
    println!("  Purpose: Get count of stored credentials");
    print!("  Executing... ");

    match cm.get_metadata(&pin_token, protocol) {
        Ok(metadata) => {
            println!("SUCCESS!");
            println!();
            println!("  [RESULTS]");
            println!(
                "     Existing credentials: {}",
                metadata.existing_credentials_count
            );
            println!(
                "     Max remaining: {}",
                metadata.max_possible_remaining_credentials
            );
        }
        Err(e) => {
            println!("FAILED");
            println!();
            println!("  [ERROR] {:?}", e);
            match e {
                KeylibError::CborCommandFailed(code) => {
                    println!("  [ERROR] CBOR command error code: {}", code);
                    println!();
                    println!("  Common causes:");
                    println!("     - PIN/UV authentication required");
                    println!("     - Command not supported by authenticator");
                }
                _ => {
                    println!("  [ERROR] Unexpected error type");
                }
            }
        }
    }
    println!();
    println!("---------------------------------------------------------------");
    println!();

    // Command 2: Enumerate RPs
    println!(">> COMMAND 0x0a/0x02: enumerateRPsBegin");
    println!("  Purpose: List all relying parties with stored credentials");
    print!("  Executing... ");

    match cm.enumerate_rps_begin(&pin_token, protocol) {
        Ok(rp_iterator) => {
            println!("SUCCESS!");
            println!();

            let mut count = 0;
            for rp_result in rp_iterator {
                match rp_result {
                    Ok(rp_info) => {
                        count += 1;
                        println!("  [RP #{}]", count);
                        println!("     ID: {}", rp_info.id);
                        if let Some(name) = &rp_info.name {
                            println!("     Name: {}", name);
                        }
                        println!("     ID Hash: {}", hex::encode(rp_info.id_hash));
                        println!();
                    }
                    Err(e) => {
                        println!("  [ERROR] Error iterating RP: {:?}", e);
                        break;
                    }
                }
            }

            if count == 0 {
                println!("  [INFO] No relying parties found (no credentials stored)");
            } else {
                println!("  [OK] Total RPs enumerated: {}", count);
            }
        }
        Err(e) => {
            println!("FAILED");
            println!();
            println!("  [ERROR] {:?}", e);
            match e {
                KeylibError::CborCommandFailed(code) => {
                    println!("  [ERROR] CBOR command error code: {}", code);
                    println!();
                    println!("  Common causes:");
                    println!("     - PIN/UV authentication required");
                    println!("     - No credentials stored on authenticator");
                    println!("     - Command not supported");
                }
                KeylibError::DoesNotExist => {
                    println!(
                        "  [INFO] No relying parties found (authenticator has no credentials)"
                    );
                }
                _ => {
                    println!("  [ERROR] Unexpected error type");
                }
            }
        }
    }
    println!();
    println!("---------------------------------------------------------------");
    println!();

    // Summary
    println!("===============================================================");
    println!("  SUMMARY");
    println!("===============================================================");
    println!();
    println!("Commands tested:");
    println!("  - 0x0a/0x01 - getCredsMetadata  (attempted)");
    println!("  - 0x0a/0x02 - enumerateRPsBegin (attempted)");
    println!();

    println!("Note: This example authenticates with PIN (123456).");
    println!("If commands fail, the authenticator may not support credential management.");
    println!();

    Ok(())
}
