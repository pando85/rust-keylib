# keylib

Rust FFI bindings for the [keylib](https://github.com/Zig-Sec/keylib) C API.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
keylib = { version = "0.1", features = ["bundled"] }
```

The `bundled` feature downloads prebuilt native libraries, so you don't need to install Zig or
libudev-dev. Just run:

```bash
cargo build
```

That's it! No additional setup required.

## Prerequisites

### Option 1: Use Prebuilt Libraries (Recommended)

Enable the `bundled` feature (shown above). This will automatically download prebuilt binaries for
your platform during build.

**Supported platforms:**

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`

### Option 2: Build from Source

If you want to build from source or need a different platform:

In case you are downloading / checking out this repository directly via git, make sure to initialize
the git submodules after cloning!

```bash
git submodule update --init
```

Tools required for building:

- Rust toolchain (stable)
- Zig compiler (for building keylib) - [Install Zig](https://ziglang.org/download/)
- libudev library (`sudo apt-get install libudev-dev` on Ubuntu/Debian)

Then omit the `bundled` feature:

```toml
[dependencies]
keylib = "0.1"
```

## Features

- Safe Rust API with proper error handling
- RAII-based resource management
- Callback bridging from Rust closures to C function pointers
- Complete callback system (UP/UV/Select/Read/Write/Delete)
- Full CTAP protocol implementation
- **PIN/UV Authentication Protocol** - Complete CTAP 2.0/2.1 PIN protocol support
  - ECDH key agreement (P-256)
  - PIN protocol V1 (AES-256-CBC) and V2 (HMAC-based encryption)
  - PIN token retrieval with permissions
  - Shared secret derivation and encryption/decryption
- **Credential Management API** - Complete implementation for managing discoverable credentials
- Examples demonstrating client and authenticator usage
- Base64-encoded credential display for debugging
- PEM-formatted certificate display in examples
- USB HID transport layer
- Client-side device enumeration and communication
- Virtual authenticator support via UHID (Linux)
- **Prebuilt binaries** - Zero-setup builds with the `bundled` feature

## API

This crate provides safe Rust abstractions over the unsafe FFI bindings.

### Key Types

- `Authenticator`: Safe wrapper for authenticator instances with callback support
- `AuthenticatorConfig`: Builder pattern for configuring authenticators with custom settings
- `AuthenticatorOptions`: Fine-grained control over authenticator capabilities (rk, up, uv,
  clientPin, credMgmt, etc.)
- `CtapCommand`: Type-safe enum for CTAP commands (MakeCredential, GetAssertion, etc.)
- `Callbacks`: Configuration for user interaction callbacks (UP/UV/Select/Read/Write/Delete)
- `CredentialManagement`: Safe API for managing discoverable credentials on authenticators
- `Error`: Error types that can occur during operations
- `Client`: Client-side API for communicating with authenticators
- `Credential`: Representation of credentials stored on authenticators

### Configurable Authenticator

You can customize the authenticator with specific AAGUID, commands, options, and extensions:

```rust
use keylib::{
    Authenticator, AuthenticatorConfig, AuthenticatorOptions,
    CallbacksBuilder, CtapCommand, UpResult
};
use std::sync::Arc;

// Configure specific capabilities
let options = AuthenticatorOptions::new()
    .with_resident_keys(true)
    .with_user_verification(Some(true))  // UV capable and configured
    .with_client_pin(Some(true))         // PIN capable and set
    .with_credential_management(Some(true));

// Build full configuration
let config = AuthenticatorConfig::builder()
    .aaguid([0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d,
             0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29, 0x7c, 0x88])
    .commands(vec![
        CtapCommand::MakeCredential,
        CtapCommand::GetAssertion,
        CtapCommand::GetInfo,
        CtapCommand::ClientPin,
    ])
    .options(options)
    .max_credentials(100)  // Allow up to 100 resident keys
    .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
    .build();

let callbacks = CallbacksBuilder::new()
    .up(Arc::new(|_info, _user, _rp| Ok(UpResult::Accepted)))
    .build();

let auth = Authenticator::with_config(callbacks, config)?;
```

**Configuration Options:**

- **AAGUID**: Custom 16-byte authenticator identifier
- **Commands**: Select which CTAP commands to enable (default: MakeCredential, GetAssertion,
  GetInfo, ClientPin, Selection)
- **Options**: Fine-tune capabilities:
  - `rk`: Resident key (discoverable credentials) support
  - `up`: User presence capability
  - `uv`: User verification (None/Some(false)/Some(true) for not capable/capable but not
    configured/capable and configured)
  - `plat`: Platform device flag
  - `client_pin`: Client PIN capability and status
  - `pin_uv_auth_token`: PIN/UV auth token support
  - `cred_mgmt`: Credential management support
  - `bio_enroll`: Biometric enrollment support
  - `large_blobs`: Large blobs support
  - `ep`: Enterprise attestation
  - `always_uv`: Always require user verification
- **Max Credentials**: Maximum number of discoverable credentials (default: 25)
- **Extensions**: List of supported extensions (e.g., "credProtect", "hmac-secret", "largeBlobKey")

See [`examples/advanced_config.rs`](keylib/examples/advanced_config.rs) for a complete
demonstration.
