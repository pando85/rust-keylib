# GitHub Copilot Instructions for rust-keylib

## Project Overview

`rust-keylib` is a safe Rust FFI wrapper around a Zig-based FIDO2/WebAuthn implementation. It provides safe, idiomatic Rust abstractions over the C API exposed by the keylib Zig library.

### Architecture

- **keylib-sys**: Low-level FFI bindings generated via `bindgen` from C headers
- **keylib**: Safe, high-level Rust API with RAII resource management
- **Build system**: Uses Zig to compile the underlying C library, statically links via Cargo

### Core Components

1. **Authenticator**: Virtual FIDO2 authenticator with callback-based user interaction
2. **Client**: CTAP client for communicating with authenticators via USB HID
3. **Transport**: Hardware communication layer (USB HID)
4. **Credential Management**: Full CTAP 2.1 credential management operations
5. **Callbacks**: Bridging Rust closures to C function pointers via trampolines

## Code Style & Conventions

### Rust Edition & Toolchain

- **Edition**: 2024
- **MSRV**: 1.91
- **Linting**: All clippy warnings treated as errors (`-D warnings`)

### Naming Conventions

- **Types**: `PascalCase` (e.g., `Authenticator`, `TransportList`)
- **Functions**: `snake_case` (e.g., `get_metadata`, `enumerate_rps_begin`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `CALLBACK_STORAGE`, `UHID_ERROR_MESSAGE`)
- **FFI wrappers**: Prefix raw C types with `Raw` (e.g., `RawTransport`, `RawCborCommand`)

### Safety & Memory Management

#### Critical Safety Rules

1. **Always document safety requirements** with `# Safety` sections for `unsafe` functions
2. **Use RAII pattern** for resource cleanup - implement `Drop` for all types wrapping raw pointers
3. **Zero-copy string handling** - Use `CStr::to_bytes()` and `str::from_utf8()` to avoid allocations
4. **Validate C string pointers** - Check for null before dereferencing in trampoline functions
5. **Global state synchronization** - Use `Mutex` for callback storage accessed from C

#### Unsafe Code Guidelines

- Minimize `unsafe` blocks - isolate to FFI boundaries only
- Document all invariants that unsafe code depends on
- Never expose raw pointers in public API
- Validate all data crossing the FFI boundary

Example:
```rust
/// # Safety
///
/// - `info`, `user`, and `rp` must be valid null-terminated C strings or null
/// - These pointers must remain valid for the duration of the call
/// - Caller must ensure no data races on global CALLBACK_STORAGE
pub unsafe extern "C" fn up_trampoline(
    info: *const c_char,
    user: *const c_char,
    rp: *const c_char,
) -> RawUpResult {
    // Check for null and validate UTF-8 without allocations
    let info_bytes = unsafe { CStr::from_ptr(info) }.to_bytes();
    let info_str = match std::str::from_utf8(info_bytes) {
        Ok(s) => s,
        Err(_) => return UpResult_UpResult_Denied,
    };
    // ...
}
```

### Error Handling

- **Return type**: Use `Result<T>` where `T` is the success type
- **Custom error type**: `KeylibError` enum covers all error cases
- **Error propagation**: Use `?` operator, avoid `unwrap()`/`expect()` in library code
- **FFI error codes**: Convert C integer error codes via `From<i32> for KeylibError`

Example error handling:
```rust
pub fn get_metadata(&mut self, pin_token: &[u8], protocol: u8) -> Result<CredentialMetadata> {
    let mut existing_count: u32 = 0;
    let mut max_remaining: u32 = 0;

    let result = unsafe {
        credential_management_get_metadata(
            self.transport.raw_handle(),
            pin_token.as_ptr(),
            protocol,
            &mut existing_count,
            &mut max_remaining,
        )
    };

    if result != CredentialManagementError_SUCCESS {
        return Err(KeylibError::from(result as i32));
    }

    Ok(CredentialMetadata { existing_count, max_remaining })
}
```

### Builder Pattern for Complex Types

Use builders for types with many optional fields:

```rust
let callbacks = CallbacksBuilder::new()
    .up(up_callback)
    .uv(uv_callback)
    .write(write_callback)
    .read(read_callback)
    .delete(delete_callback)
    .build();

let auth = Authenticator::new(callbacks)?;
```

### Documentation Standards

#### Module-level Documentation

Include comprehensive module docs with:
- Purpose and functionality overview
- Code examples demonstrating typical usage
- Important caveats or limitations

Example:
```rust
//! Credential Management
//!
//! This module provides functionality for managing discoverable credentials
//! stored on a FIDO2 authenticator. It allows you to:
//!
//! - Query metadata about stored credentials
//! - Enumerate relying parties (RPs) with credentials
//! - Enumerate credentials for a specific RP
//! - Delete credentials by ID
//! - Update user information for credentials
//!
//! All operations require a valid PIN token with credential management (0x04) permission.
//!
//! # Example
//!
//! ```no_run
//! # use keylib::*;
//! # fn main() -> Result<()> {
//! let transport_list = TransportList::enumerate()?;
//! let mut transport = transport_list.get(0).unwrap();
//! transport.open()?;
//!
//! let mut cm = CredentialManagement::new(&mut transport);
//! let metadata = cm.get_metadata(pin_token, 2)?;
//! # Ok(())
//! # }
//! ```
```

#### Function Documentation

- **Arguments section** (`# Arguments`) for all parameters
- **Returns section** (`# Returns`) describing success value
- **Errors section** (`# Errors`) for all failure cases
- **Safety section** (`# Safety`) for unsafe functions
- **Examples** for complex or non-obvious usage

## API Design Patterns

### Resource Lifetime Management

1. **Ownership model**: Rust types own their FFI resources
2. **Drop implementation**: Always free C resources in `Drop`
3. **No manual cleanup**: Users never call `free` or `deinit` directly

```rust
impl Drop for Transport {
    fn drop(&mut self) {
        unsafe { transport_free(self.raw) };
    }
}
```

### Iterator Pattern

Prefer standard Rust iterators over index-based access:

```rust
pub fn iter(&self) -> TransportListIter<'_> {
    TransportListIter {
        list: self,
        index: 0,
    }
}

impl<'a> Iterator for TransportListIter<'a> {
    type Item = Transport;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.list.len() {
            let transport = self.list.get(self.index);
            self.index += 1;
            transport
        } else {
            None
        }
    }
}
```

### Callback Design

- **Type aliases**: Define clear callback signatures with `Arc<dyn Fn>` for thread safety
- **Zero-copy**: Pass borrowed data to callbacks when possible
- **Conversion methods**: Provide `to_owned()` if users need to extend lifetime

```rust
/// Write callback type for storing credential data (zero-copy)
///
/// The credential data is borrowed from the FFI layer and is only valid
/// during the callback invocation. Use `CredentialRef::to_owned()` if you
/// need to store the credential beyond the callback scope.
pub type WriteCallback = Arc<dyn Fn(&str, &str, CredentialRef) -> Result<()> + Send + Sync>;
```

## Testing Guidelines

### Test Organization

- **Unit tests**: In `#[cfg(test)] mod unit_tests` within source files
- **Integration tests**: In `tests/` directory, require `--features integration-tests`
- **Examples as tests**: Examples in `examples/` serve as integration tests

### Hardware-Dependent Tests

Tests requiring physical FIDO2 devices should gracefully skip when hardware is unavailable:

```rust
#[test]
fn test_authenticator_get_info() {
    let list = match TransportList::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("Failed to enumerate transports: {:?}", e);
            return; // Skip test if no hardware
        }
    };

    if list.is_empty() {
        eprintln!("No devices available, skipping test");
        return;
    }
    // ... rest of test
}
```

### Test Coverage

- All public APIs should have at least one test
- Error paths should be tested
- Examples should compile and demonstrate real usage

## Build System

### Dependencies

- **Zig compiler**: Required for building keylib C library
- **hidapi**: USB HID communication (statically linked)
- **bindgen**: FFI binding generation at build time

### Build Process

1. `build.rs` invokes `zig build install` to compile keylib
2. `bindgen` generates Rust bindings from C headers
3. Static libraries linked into final Rust binary

### Feature Flags

- `static`: Static linking mode (default behavior)
- `integration-tests`: Enable hardware-dependent integration tests

## Common Patterns & Anti-Patterns

### ✅ DO

- Use `Result<T>` for all fallible operations
- Document all public items with rustdoc comments
- Implement `Drop` for types wrapping raw pointers
- Use builder pattern for types with many optional fields
- Validate data at FFI boundaries
- Keep unsafe blocks minimal and well-documented

### ❌ DON'T

- Expose raw pointers in public APIs (except in `raw` module)
- Use `unwrap()` or `expect()` in library code
- Allocate unnecessarily when converting C strings
- Forget to implement `Send + Sync` bounds for callbacks
- Expose mutable global state without synchronization
- Implement manual memory management (use RAII)

## Examples

### Adding a New FFI Wrapper

When wrapping a new C API function:

1. **Add raw binding** (if not auto-generated by bindgen)
2. **Create safe wrapper** with appropriate type conversions
3. **Document thoroughly** with examples and safety notes
4. **Handle errors** using `Result<T>`
5. **Add tests** demonstrating usage

Example template:
```rust
/// Brief description of what this function does
///
/// # Arguments
/// * `param1` - Description
/// * `param2` - Description
///
/// # Returns
/// Description of success value
///
/// # Errors
/// Description of when/why this fails
///
/// # Example
/// ```no_run
/// # use keylib::*;
/// # fn main() -> Result<()> {
/// let result = my_function(param1, param2)?;
/// # Ok(())
/// # }
/// ```
pub fn my_function(param1: Type1, param2: Type2) -> Result<ReturnType> {
    // Validation
    if param1.is_invalid() {
        return Err(KeylibError::Other);
    }

    // FFI call
    let result = unsafe {
        raw_c_function(
            param1.as_raw(),
            param2.as_ptr(),
        )
    };

    // Error handling
    if result != SUCCESS_CODE {
        return Err(KeylibError::from(result));
    }

    // Convert and return
    Ok(ReturnType::from_raw(result))
}
```

## Project-Specific Context

### CTAP Protocol Implementation

- Implements CTAP 2.1 specification for FIDO2/WebAuthn
- Client-side operations: getInfo, makeCredential, getAssertion
- Authenticator-side operations: Full protocol handling with callbacks
- Credential management: All 7 CTAP operations fully implemented

### Key Abstractions

- **Authenticator**: Software authenticator with customizable behavior via callbacks
- **Transport**: Hardware communication layer (currently USB HID only)
- **Client**: Issues CTAP commands to authenticators
- **CborCommand/CborPromise**: Async-style command execution with polling

### Zig Integration

- Core implementation in Zig for memory safety and performance
- Exposes C-compatible API via `bindings/c/include/keylib.h`
- Static linking ensures no runtime dependencies

### Virtual Device Support

- UHID kernel module support for virtual USB HID devices
- Enables testing without physical hardware
- Requires specific Linux permissions (see `UHID_ERROR_MESSAGE`)

## Maintenance Notes

### When Adding New Features

1. Update relevant module documentation
2. Ensure all new public APIs are documented

### IMPORTANT: Do NOT create summary documents

- NEVER create markdown files to document changes (like IMPLEMENTATION.md, TESTING.md, etc.)
- NEVER summarize your work in separate documentation files
- Code documentation and inline comments are sufficient

### When Fixing Bugs

1. Add regression test before fix
2. Document root cause in commit message
3. Update any affected examples
4. Check for similar issues in related code

### Versioning

- Follows Semantic Versioning (SemVer)
- Current version: 0.1.0 (pre-1.0, expect breaking changes)
- Version managed in workspace root `Cargo.toml`

## Additional Resources

- **CTAP Specification**: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- **WebAuthn Specification**: https://www.w3.org/TR/webauthn-2/
- **Zig keylib**: `keylib-sys/keylib/` (git submodule)
- **Repository**: https://github.com/pando85/rust-keylib
