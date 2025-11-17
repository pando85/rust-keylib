# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`rust-keylib` is a safe Rust FFI wrapper around a Zig-based FIDO2/WebAuthn implementation (keylib). It provides idiomatic Rust abstractions over the C API exposed by the keylib Zig library.

**Workspace Structure:**
- **keylib-sys**: Low-level FFI bindings (auto-generated via bindgen from C headers)
- **keylib**: Safe, high-level Rust API with RAII resource management

## Common Commands

### Building
```bash
# Standard build
cargo build

# Build with prebuilt libraries (no Zig/libudev required)
cargo build --features bundled

# Build from source (requires Zig compiler and libudev-dev)
git submodule update --init
cargo build
```

### Testing
```bash
# Run basic tests with linting
make test

# Run integration tests (requires hardware or virtual authenticator)
make test-integration

# Run E2E WebAuthn tests (requires UHID permissions - see DEVELOPMENT.md)
make test-e2e

# Run all tests
make test-all
```

### Linting
```bash
# Format and lint
make lint

# Format and lint with auto-fixes
make lint-fix

# Individual checks
cargo fmt                                              # Format code
cargo clippy --all-targets --all-features -- -D warnings  # Lint
```

### Examples
```bash
# Run examples (located in keylib/examples/)
cargo run --example authenticator
cargo run --example client
cargo run --example credential_management
cargo run --example pin_protocol
cargo run --example custom_commands
cargo run --example webauthn_flow
```

### Pre-commit
```bash
make pre-commit-install  # Install pre-commit hooks
make pre-commit          # Run pre-commit on all files
```

## Architecture

### Multi-Layer Design

**Layer 1: Zig Core (keylib-sys/keylib/)**
- Core FIDO2/CTAP implementation in Zig
- Exposes C API via `bindings/c/include/keylib.h`
- Statically linked into Rust binary

**Layer 2: FFI Bindings (keylib-sys/)**
- `build.rs` invokes `zig build install` to compile keylib C library
- `bindgen` generates Rust bindings from C headers
- Provides raw unsafe FFI functions

**Layer 3: Safe Rust API (keylib/)**
- Safe wrappers with RAII resource management
- Type-safe CTAP protocol operations
- Builder patterns for complex configuration

### Core Components

**Authenticator (keylib/src/authenticator.rs)**
- Virtual FIDO2 authenticator with callback-based user interaction
- Configurable via `AuthenticatorConfig` and `AuthenticatorOptions`
- Supports custom CTAP commands (0x40-0xFF range)
- Stores credentials in memory (HashMap)

**Client (keylib/src/client/)**
- CTAP client for communicating with authenticators
- Issues commands: getInfo, makeCredential, getAssertion, clientPin
- Uses builder pattern for request construction
- Asynchronous-style command execution via `CborCommand`/`CborCommandResult`

**Transport Layer (keylib/src/client/mod.rs)**
- USB HID communication via hidapi
- Transport enumeration and lifecycle management
- CTAP HID protocol implementation in `ctaphid.rs`

**Credential Management (keylib/src/credential_management.rs)**
- Full CTAP 2.1 credential management operations
- Query metadata, enumerate RPs, enumerate credentials
- Delete credentials, update user information
- All operations require PIN token with credential management permission (0x04)

**Callbacks (keylib/src/callbacks.rs)**
- Bridges Rust closures to C function pointers via trampolines
- Six callback types: UP (user presence), UV (user verification), Select, Read, Write, Delete
- Thread-safe via `Arc<dyn Fn + Send + Sync>`
- Global state synchronized with `Mutex`

**PIN/UV Protocol (keylib/src/client_pin.rs)**
- CTAP 2.0/2.1 PIN protocol support
- ECDH key agreement (P-256)
- PIN protocol V1 (AES-256-CBC) and V2 (HMAC-based)
- PIN token retrieval with granular permissions

**Virtual Device Support (keylib/src/uhid.rs)**
- Linux UHID kernel module integration
- Creates virtual USB HID devices at `/dev/uhid`
- Enables E2E testing without physical hardware
- Requires specific permissions (fido group membership)

### Bundled Feature

The `bundled` feature flag enables zero-setup builds:
- Downloads prebuilt native libraries for your platform during build
- Eliminates need for Zig compiler and libudev-dev
- Implemented in `keylib-sys/build/bundled.rs`
- Supported platforms: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl

## Code Style & Safety

### Rust Settings
- **Edition**: 2024
- **MSRV**: 1.91
- **Linting**: All clippy warnings are errors (`-D warnings`)

### Safety Rules
1. **Document safety requirements** - Use `# Safety` sections for all `unsafe` functions
2. **RAII pattern** - Implement `Drop` for all types wrapping raw pointers; no manual cleanup exposed
3. **Zero-copy string handling** - Use `CStr::to_bytes()` + `str::from_utf8()` to avoid allocations
4. **Validate FFI boundaries** - Check for null pointers, validate UTF-8, check array bounds
5. **Global state synchronization** - Use `Mutex` for callback storage accessed from C

### Error Handling
- Return `Result<T>` for all fallible operations
- Custom error type: `KeylibError` enum
- Use `?` operator, avoid `unwrap()`/`expect()` in library code
- Convert C error codes via `From<i32> for KeylibError`

### Naming Conventions
- **FFI wrappers**: Prefix raw C types with `Raw` (e.g., `RawTransport`)
- **Modules**: snake_case
- **Types**: PascalCase
- **Functions**: snake_case
- **Constants**: SCREAMING_SNAKE_CASE

## Testing Architecture

### Test Organization

**Unit tests**: In `#[cfg(test)] mod tests` within source files

**Integration tests** (keylib/tests/):
- `integration.rs` - Basic integration tests
- `credential_storage_test.rs` - Credential storage tests
- `e2e_webauthn_test.rs` - Full end-to-end WebAuthn flow

**Examples as tests**: All examples in `keylib/examples/` serve as integration tests

### Hardware-Dependent Tests

Integration and E2E tests gracefully skip when hardware/permissions are unavailable. They should check for device availability before proceeding:

```rust
let list = match TransportList::enumerate() {
    Ok(list) => list,
    Err(e) => {
        eprintln!("No devices available: {:?}", e);
        return; // Skip test
    }
};
```

### E2E WebAuthn Testing

The `e2e_webauthn_test.rs` test provides comprehensive testing:

**Architecture:**
- **Authenticator Thread**: Virtual authenticator via UHID, runs CTAP HID protocol
- **Test Thread (Client)**: Enumerates devices, sends commands via USB HID transport
- **Communication**: Both threads use Linux UHID kernel module (`/dev/uhid`)

**Requirements:**
- UHID kernel module loaded (`sudo modprobe uhid`)
- User in `fido` group
- Udev rules for UHID access (see DEVELOPMENT.md)

## Important Patterns

### Builder Pattern
Used for complex types with many optional fields:
```rust
let config = AuthenticatorConfig::builder()
    .aaguid([...])
    .commands(vec![...])
    .options(options)
    .max_credentials(100)
    .extensions(vec![...])
    .build();
```

### Callback Design
- Type aliases with `Arc<dyn Fn + Send + Sync>` for thread safety
- Zero-copy: pass borrowed data when possible
- Provide `to_owned()` methods for lifetime extension

### Resource Lifetime
- Rust types own their FFI resources
- `Drop` implementation automatically frees C resources
- Users never call `free` or `deinit` directly

## Key Abstractions

**CborCommand/CborCommandResult**: Async-style CTAP command execution with polling:
```rust
let command = client.make_credential().rp(...).user(...).send()?;
let result = command.wait()?; // Poll until complete
```

**CredentialRef**: Zero-copy credential view that borrows from FFI layer. Use `to_owned()` to extend lifetime beyond callback scope.

**CustomCommand**: Extend CTAP protocol with vendor-specific commands (0x40-0xFF). Provide handler closure that processes request and writes response.

## What NOT to Do

- ❌ Expose raw pointers in public APIs (except in internal modules)
- ❌ Use `unwrap()` or `expect()` in library code
- ❌ Allocate unnecessarily when converting C strings
- ❌ Forget `Send + Sync` bounds for callbacks
- ❌ Implement manual memory management (always use RAII)
- ❌ Create summary documentation files (IMPLEMENTATION.md, TESTING.md, etc.)

## Additional Resources

- **CTAP Specification**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
- **WebAuthn Specification**: https://www.w3.org/TR/webauthn-2/
- **Zig keylib**: Located in `keylib-sys/keylib/` (git submodule)
- **Repository**: https://github.com/pando85/rust-keylib
