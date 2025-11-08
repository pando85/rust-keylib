# keylib

Rust FFI bindings for the keylib C API.

## Prerequisites

In case you are downloading / checking out this repository directly via git, make sure to initialize
the git submodules after cloning!

```bash
git submodule update --init
```

Tools required for building:

- Rust toolchain (stable)
- Zig compiler (for building keylib)
- hidapi library

## Building

```bash
cargo build
```

## Running the Examples

```bash
cargo run --example client       # Client that sends CTAP commands
cargo run --example authenticator # Authenticator with callbacks, base64 credentials, and PEM certificates
cargo run --example credential_management # Credential management operations
```

## API

This crate provides safe Rust abstractions over the unsafe FFI bindings.

### Key Types

- `Authenticator`: Safe wrapper for authenticator instances with callback support
- `Callbacks`: Configuration for user interaction callbacks (UP/UV/Select/Read/Write/Delete)
- `CredentialManagement`: Safe API for managing discoverable credentials on authenticators
- `Error`: Error types that can occur during operations

## Features

- Safe Rust API with proper error handling
- RAII-based resource management
- Callback bridging from Rust closures to C function pointers
- Complete callback system (UP/UV/Select/Read/Write/Delete)
- Full CTAP protocol implementation
- **Credential Management API** - Complete implementation for managing discoverable credentials
- Examples demonstrating client and authenticator usage
- Base64-encoded credential display for debugging
- PEM-formatted certificate display in examples
- PIN/UV authentication token handling
- USB HID transport layer
- Client-side device enumeration and communication
- Static linking to keylib library

## Safety

The safe API ensures memory safety and proper resource cleanup. Raw FFI bindings are available in
the `raw` module for advanced use cases.

## Implementation Status

### ✅ Completed

- Callback system with trampoline functions (UP/UV/Select/Read/Write/Delete)
- Authenticator initialization and lifecycle management
- Basic CTAP command handling (authenticatorGetInfo)
- CBOR serialization/deserialization for responses
- **Complete Credential Management API** - All 7 CTAP operations implemented
- Comprehensive examples

### 🚧 In Progress / TODO

## Limitations

- CTAP message handling is limited to authenticatorGetInfo
- No USB HID communication (examples use direct API calls)
- **Credential management is fully implemented** - All operations available through safe Rust API
