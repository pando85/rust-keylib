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
- `Callbacks`: Configuration for user interaction callbacks (UP/UV/Select/Read/Write/Delete)
- `CredentialManagement`: Safe API for managing discoverable credentials on authenticators
- `Error`: Error types that can occur during operations
- `Client`: Client-side API for communicating with authenticators
- `Credential`: Representation of credentials stored on authenticators
