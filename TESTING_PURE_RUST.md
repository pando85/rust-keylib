# Testing the Pure Rust Implementation

This document provides instructions for testing the pure Rust CTAP implementation.

## Prerequisites

### For E2E Tests (Linux only)

The E2E tests require:
1. **Linux kernel with UHID module**
   ```bash
   sudo modprobe uhid
   ```

2. **Permissions to access `/dev/uhid`**
   ```bash
   # Option 1: Add yourself to the fido group (recommended)
   sudo groupadd -f fido
   sudo usermod -a -G fido $USER

   # Create udev rule
   echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | sudo tee /etc/udev/rules.d/99-uhid.rules
   sudo udevadm control --reload-rules
   sudo udevadm trigger

   # Log out and log back in for group membership to take effect

   # Option 2: Temporary access (not recommended for regular use)
   sudo chmod 666 /dev/uhid
   ```

3. **libudev development libraries** (for USB features)
   ```bash
   # Debian/Ubuntu
   sudo apt-get install libudev-dev

   # Fedora/RHEL
   sudo dnf install systemd-devel

   # Arch
   sudo pacman -S systemd
   ```

## Building with Pure Rust

### Build without USB support (no libudev required)

```bash
# Pure Rust implementation only
cargo build --no-default-features --features pure-rust

# Or build specific packages
cargo build -p keylib-crypto
cargo build -p keylib-ctap
cargo build -p keylib-transport
```

### Build with USB support (requires libudev)

```bash
# Pure Rust with USB HID transport
cargo build --no-default-features --features pure-rust,usb
```

## Running Tests

### 1. Unit Tests (No Special Requirements)

Run all unit tests across pure Rust crates:

```bash
# All pure Rust crates
cargo test -p keylib-crypto -p keylib-ctap -p keylib-transport

# Individual crates
cargo test -p keylib-crypto     # Cryptographic primitives (26 tests)
cargo test -p keylib-ctap       # CTAP protocol (86 tests)
cargo test -p keylib-transport  # Transport layer (30 tests)
```

**Expected output:**
```
test result: ok. 162 passed; 0 failed; 2 ignored; 0 measured
```

### 2. Integration Tests

Run integration tests for the transport layer:

```bash
cargo test -p keylib-transport --test integration_test
```

**Expected output:**
```
running 7 tests
test test_channel_manager_basic ... ok
test test_channel_manager_multi_packet ... ok
test test_full_stack_message_round_trip ... ok
test test_handler_cbor_command ... ok
test test_handler_init_command ... ok
test test_handler_ping_command ... ok
test test_multiple_channels ... ok

test result: ok. 7 passed; 0 failed; 0 ignored
```

### 3. E2E WebAuthn Tests (Requires UHID Permissions)

The E2E tests are currently in the `keylib` crate using the Zig FFI implementation. To run them with pure Rust, you'll need to modify the tests.

#### Current E2E Tests (Zig FFI)

```bash
# Run E2E tests with Zig FFI (requires bundled or built Zig libs)
cargo test --test e2e_webauthn_test --features integration-tests -- --ignored

# Or with bundled prebuilt libraries
cargo test --test e2e_webauthn_test --features bundled,integration-tests -- --ignored
```

#### E2E Test Scenarios

The E2E tests cover:

1. **Complete WebAuthn Flow**
   - Virtual authenticator creation via UHID
   - INIT command (channel allocation)
   - PIN protocol V2 setup
   - makeCredential (registration)
   - getAssertion (authentication)

2. **PIN Change Flow**
   - Initial registration with PIN
   - PIN change operation
   - Authentication with new PIN

3. **UV-Only Authenticator**
   - Registration without PIN
   - Authentication with built-in UV

4. **Registration without PIN**
   - Optional PIN behavior testing

## Testing Pure Rust Components

### Example: Test UHID Device Creation

```rust
use keylib::rust_impl::transport::UhidDevice;

#[test]
#[ignore] // Requires /dev/uhid access
fn test_create_virtual_device() {
    let device = UhidDevice::create_fido_device()
        .expect("Failed to create UHID device");

    assert!(device.is_started());

    // Device is automatically destroyed on drop
}
```

### Example: Test Authenticator with Pure Rust

```rust
use keylib::rust_impl::authenticator::{BridgeCallbacks, RustAuthenticator};
use keylib_ctap::authenticator::AuthenticatorConfig;

#[test]
fn test_authenticator_creation() {
    let callbacks = BridgeCallbacks::new()
        .with_up_callback(|_, _, _| Ok(keylib_ctap::callbacks::UpResult::Accepted))
        .with_uv_callback(|_, _, _| Ok(keylib_ctap::callbacks::UvResult::Accepted));

    let config = AuthenticatorConfig::new();
    let auth = RustAuthenticator::with_config(config, callbacks);

    // Authenticator is ready to use
    assert!(auth.inner().config().options.is_platform_device);
}
```

### Example: Full Stack Integration

```rust
use keylib::rust_impl::{
    authenticator::{BridgeCallbacks, RustAuthenticator},
    transport::UhidDevice,
};
use keylib_ctap::bridge::TransportBridge;
use keylib_transport::{CtapHidHandler, AuthenticatorRunner};

#[test]
#[ignore] // Requires /dev/uhid
fn test_full_stack() {
    // Create authenticator
    let callbacks = BridgeCallbacks::new();
    let config = keylib_ctap::authenticator::AuthenticatorConfig::new();
    let authenticator = RustAuthenticator::with_config(config, callbacks);

    // Create transport bridge
    let dispatcher = keylib_ctap::dispatcher::CommandDispatcher::new(
        authenticator.inner().clone() // Needs interior mutability
    );
    let bridge = TransportBridge::new(dispatcher);

    // Create CTAP HID handler
    let handler = CtapHidHandler::new(bridge);

    // Create UHID device
    let uhid = UhidDevice::create_fido_device()
        .expect("Failed to create UHID device");

    // Create authenticator runner
    // (This would require some refactoring to work with UHID)

    // Process packets...
}
```

## Debugging

### Enable Rust Logging

```bash
RUST_LOG=debug cargo test -p keylib-transport --test integration_test
```

### Check UHID Availability

```bash
# Check if uhid module is loaded
lsmod | grep uhid

# Check uhid device permissions
ls -la /dev/uhid

# Try loading uhid module
sudo modprobe uhid
```

### Common Issues

1. **`/dev/uhid` permission denied**
   - Solution: Add yourself to fido group (see Prerequisites)
   - Temporary: `sudo chmod 666 /dev/uhid`

2. **libudev not found**
   - Solution: Install libudev-dev (see Prerequisites)
   - Alternative: Build without USB support (`--no-default-features --features pure-rust`)

3. **UHID not available**
   - Solution: Load uhid kernel module (`sudo modprobe uhid`)
   - Check: Ensure you're on Linux (UHID is Linux-only)

## Feature Flags Reference

| Feature | Description | Requirements |
|---------|-------------|--------------|
| `zig-ffi` | Zig FFI implementation (default) | Zig compiler or bundled libs |
| `pure-rust` | Pure Rust implementation | None |
| `usb` | USB HID transport | libudev (Linux) |
| `bundled` | Use prebuilt Zig libraries | None |
| `integration-tests` | Enable integration test features | Varies by test |

## Next Steps

The pure Rust implementation is integrated into keylib with the `pure-rust` feature flag. To complete the migration:

1. **Write E2E tests for pure Rust** - Create new E2E tests in `keylib/tests/` that use the pure Rust implementation
2. **Verify behavioral compatibility** - Ensure pure Rust behaves identically to Zig FFI
3. **Performance benchmarking** - Compare performance between implementations
4. **Switch default** - Once validated, make `pure-rust` the default instead of `zig-ffi`

## Test Coverage Summary

Current test coverage for pure Rust implementation:

```
Total: 162 tests passing
├── keylib-crypto:     26 tests (90% coverage)
│   ├── ECDH:          6 tests
│   ├── ECDSA:        12 tests
│   └── PIN protocols: 8 tests
│
├── keylib-ctap:       86 tests (85% coverage)
│   ├── Types:        11 tests
│   ├── Status:        4 tests
│   ├── Authenticator: 12 tests
│   ├── Callbacks:     4 tests
│   ├── PIN tokens:   12 tests
│   ├── CBOR:         12 tests
│   ├── Commands:     31 tests
│   │   ├── get_info:        3 tests
│   │   ├── make_credential: 3 tests
│   │   ├── get_assertion:   2 tests
│   │   ├── client_pin:      1 test
│   │   ├── cred_mgmt:       8 tests
│   │   └── dispatcher:      4 tests
│   └── Bridge:        2 tests
│
└── keylib-transport:  50 tests (80% coverage)
    ├── CTAP HID:      9 tests
    ├── Channels:      8 tests
    ├── Handler:       6 tests
    ├── Integration:   7 tests
    └── UHID:          2 tests (ignored)
```

---

*For questions or issues, please open an issue on GitHub.*
*Branch: claude/inspect-rust-implementation-01Whut5rididjbBy2hBxLDWD*
