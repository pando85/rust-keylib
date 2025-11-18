# Pure Rust Interface Alignment Plan

**Version**: 1.0
**Date**: 2025-11-18
**Status**: Proposal - Awaiting Review

## Executive Summary

This document outlines a comprehensive plan to align the pure Rust CTAP implementation's interface with the existing Zig FFI interface, enabling the same test suite (especially E2E WebAuthn tests) to run on both implementations.

**Goal**: Make `keylib` tests implementation-agnostic so they can validate both `zig-ffi` and `pure-rust` backends without modification.

**Current Situation**:
- ✅ Pure Rust CTAP core implementation complete (keylib-crypto, keylib-ctap, keylib-transport)
- ✅ Integrated with keylib crate via feature flags (`pure-rust`, `zig-ffi`)
- ✅ `pure-rust` is now the default feature
- ❌ E2E tests only work with `zig-ffi` due to interface mismatches
- ❌ Different error types, credential structures, and client APIs

## Gap Analysis

### 1. Client API

**Zig FFI Has:**
```rust
// keylib/src/client/mod.rs
pub struct Client;
impl Client {
    pub fn make_credential(transport: &mut Transport, request: MakeCredentialRequest) -> Result<Vec<u8>>
    pub fn get_assertion(transport: &mut Transport, request: GetAssertionRequest) -> Result<Vec<u8>>
    pub fn authenticator_get_info(transport: &mut Transport) -> Result<CborCommand>
}

pub struct Transport { /* USB HID transport */ }
pub struct TransportList { /* enumerate USB devices */ }
pub struct CborCommand { /* async command execution */ }
pub struct CborCommandResult { /* command results */ }
```

**Pure Rust Has:**
```rust
// keylib-ctap/src/authenticator.rs
pub struct Authenticator<C: Callbacks> { /* direct authenticator */ }
impl Authenticator {
    pub fn handle_command(&mut self, cmd: &[u8]) -> Result<Vec<u8>, StatusCode>
}

// keylib-transport/src/lib.rs
// USB transport exists but not exposed through keylib/src/rust_impl
```

**Gap**: Pure Rust lacks the high-level `Client` API for WebAuthn flows.

### 2. Transport Layer

**Zig FFI Has:**
```rust
pub struct Transport {
    pub fn open(&mut self) -> Result<()>
    pub fn close(&mut self)
    pub fn read(&mut self, buffer: &mut [u8], timeout_ms: i32) -> Result<usize>
    pub fn write(&mut self, data: &[u8]) -> Result<()>
}

pub struct TransportList {
    pub fn enumerate() -> Result<Self>
    pub fn get(&self, index: usize) -> Option<Transport>
}
```

**Pure Rust Has:**
```rust
// keylib-transport/src/usb.rs (not exposed in keylib::rust_impl)
#[cfg(feature = "usb")]
pub struct UsbTransport { /* HID transport */ }

// keylib-transport/src/ctap_hid.rs
pub struct CtapHidHandler<C: CommandHandler> { /* packet handler */ }
```

**Gap**: Pure Rust USB transport not exposed through unified API in `keylib::rust_impl::transport`.

### 3. Error Types

**Zig FFI Has:**
```rust
// keylib/src/error.rs
pub enum KeylibError {
    Success,
    DoesAlreadyExist,
    DoesNotExist,
    KeyStoreFull,
    OutOfMemory,
    Timeout,
    Other,
    InvalidCallbackResult,
    CborCommandFailed(i32),
    InvalidClientDataHash,
}
pub type Error = KeylibError;
pub type Result<T> = std::result::Result<T, KeylibError>;
```

**Pure Rust Has:**
```rust
// keylib-ctap/src/status.rs
pub enum StatusCode {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    // ... CTAP status codes
}
```

**Gap**: Different error types make test code incompatible.

### 4. Credential Types

**Zig FFI Has:**
```rust
// keylib/src/credential.rs
pub struct Credential {
    pub id: Vec<u8>,
    pub rp: RelyingParty,      // nested struct
    pub user: User,            // nested struct
    pub sign_count: u32,
    pub alg: i32,
    pub private_key: Vec<u8>,
    pub created: i64,
    pub discoverable: bool,
    pub extensions: Extensions, // nested struct
}

pub struct CredentialRef<'a> { /* borrowed version */ }
impl CredentialRef {
    pub fn to_owned(&self) -> Credential
    pub fn to_bytes(&self) -> Result<Vec<u8>>
}
```

**Pure Rust Has:**
```rust
// keylib-ctap/src/types.rs
pub struct Credential {
    pub id: Vec<u8>,
    pub rp_id: String,         // flat structure
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub sign_count: u32,
    pub algorithm: i32,
    pub private_key: Vec<u8>,
    pub created: i64,
    pub discoverable: bool,
    pub cred_protect: u8,
}
```

**Gap**: Different struct layouts make credential operations incompatible.

### 5. Authenticator API

**Zig FFI Has:**
```rust
// keylib/src/authenticator.rs
pub struct Authenticator { /* opaque FFI handle */ }
impl Authenticator {
    pub fn new(config: AuthenticatorConfig, callbacks: Callbacks) -> Result<Self>
    pub fn set_pin_hash(hash: &[u8; 32])
    pub fn run(&mut self) -> Result<()>
    pub fn stop(&mut self)
}

pub struct Callbacks {
    pub up_callback: Option<UpCallback>,
    pub uv_callback: Option<UvCallback>,
    pub read_callback: Option<ReadCallback>,
    pub write_callback: Option<WriteCallback>,
    pub delete_callback: Option<DeleteCallback>,
    pub read_first_callback: Option<ReadFirstCallback>,
}
```

**Pure Rust Has:**
```rust
// keylib/src/rust_impl/authenticator.rs
pub struct RustAuthenticator {
    inner: CtapAuthenticator<BridgeCallbacks>
}

pub struct BridgeCallbacks {
    // Trait-based callbacks
}
impl UserInteractionCallbacks for BridgeCallbacks { /* ... */ }
impl CredentialStorageCallbacks for BridgeCallbacks { /* ... */ }
```

**Gap**: Different callback systems and authenticator lifecycle management.

### 6. UHID Virtual Device Support

**Zig FFI Has:**
```rust
// keylib/src/uhid.rs
pub struct Uhid { /* raw FFI handle */ }
impl Uhid {
    pub fn create() -> Result<Self>
    pub fn write_event(&mut self, data: &[u8]) -> Result<()>
    pub fn read_event(&mut self, buffer: &mut [u8]) -> Result<usize>
}
```

**Pure Rust Has:**
```rust
// keylib-transport/src/uhid.rs
#[cfg(target_os = "linux")]
pub struct UhidDevice { /* native implementation */ }
impl UhidDevice {
    pub fn create_fido_device() -> Result<Self, std::io::Error>
    pub fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error>
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error>
}
```

**Gap**: UHID device available but not exposed through `keylib::rust_impl` API, different error types.

### 7. PIN Protocol Support

**Zig FFI Has:**
```rust
// keylib/src/client_pin.rs
pub struct PinUvAuthEncapsulation { /* state machine */ }
impl PinUvAuthEncapsulation {
    pub fn new(protocol: PinProtocol) -> Result<Self>
    pub fn initialize(&mut self, transport: &mut Transport) -> Result<()>
    pub fn get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        transport: &mut Transport,
        pin: &str,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Vec<u8>>
    pub fn authenticate(&self, data: &[u8], pin_token: &[u8]) -> Result<Vec<u8>>
}
```

**Pure Rust Has:**
```rust
// keylib-crypto/src/pin.rs
pub mod pin_protocol_v1 { /* functions */ }
pub mod pin_protocol_v2 { /* functions */ }
// No high-level encapsulation wrapper
```

**Gap**: Pure Rust has PIN protocol primitives but lacks high-level state machine API.

### 8. Request Builders

**Zig FFI Has:**
```rust
// keylib/src/client/requests.rs
pub struct MakeCredentialRequest {
    pub client_data_hash: ClientDataHash,
    pub rp: RelyingParty,
    pub user: User,
    pub pin_uv_auth: Option<PinUvAuth>,
    pub timeout_ms: i32,
}

pub struct GetAssertionRequest {
    pub client_data_hash: ClientDataHash,
    pub rp_id: String,
    pub allow_list: Vec<CredentialDescriptor>,
    pub pin_uv_auth: Option<PinUvAuth>,
    pub timeout_ms: i32,
}
```

**Pure Rust Has:**
- CBOR encoding/decoding in `keylib-ctap/src/cbor.rs`
- No builder pattern for requests

**Gap**: Missing request builder structs for ergonomic API.

## Interface Alignment Strategy

### Design Principles

1. **Abstraction Over Implementation**: Create a common trait-based interface that both implementations satisfy
2. **Minimal Code Duplication**: Share types where possible (errors, credentials, requests)
3. **Feature-Gated Implementations**: Keep implementations separate, unified interface
4. **Backward Compatibility**: Don't break existing zig-ffi users
5. **Progressive Enhancement**: Start with most critical gaps (Client API, Transport)

### Proposed Architecture

```
keylib/src/
├── lib.rs                    # Feature-gated re-exports
├── common/                   # NEW: Shared types and traits
│   ├── mod.rs
│   ├── error.rs             # Unified Error type
│   ├── credential.rs        # Unified Credential type
│   ├── client.rs            # Client trait + request builders
│   └── transport.rs         # Transport trait
├── zig_ffi/                  # RENAMED from current modules
│   ├── authenticator.rs     # Zig FFI authenticator
│   ├── client.rs            # Zig FFI client (trait impl)
│   └── transport.rs         # Zig FFI transport (trait impl)
└── rust_impl/                # Pure Rust implementation
    ├── authenticator.rs     # Current
    ├── client.rs            # NEW: Pure Rust client (trait impl)
    └── transport.rs         # ENHANCED: Expose USB + UHID
```

### Key Components to Create

#### 1. Unified Error Type (`keylib/src/common/error.rs`)

```rust
/// Unified error type for both implementations
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    Success,
    DoesAlreadyExist,
    DoesNotExist,
    KeyStoreFull,
    OutOfMemory,
    Timeout,
    Other,
    InvalidCallbackResult,
    InvalidClientDataHash,
    // CTAP status codes
    CtapError(u8),
    // IO errors
    IoError(String),
}

impl From<keylib_ctap::StatusCode> for Error { /* ... */ }
impl From<KeylibError> for Error { /* ... */ }
impl From<std::io::Error> for Error { /* ... */ }
```

#### 2. Unified Credential Type (`keylib/src/common/credential.rs`)

```rust
/// Unified credential type (matches zig-ffi structure)
pub struct Credential {
    pub id: Vec<u8>,
    pub rp: RelyingParty,
    pub user: User,
    pub sign_count: u32,
    pub alg: i32,
    pub private_key: Vec<u8>,
    pub created: i64,
    pub discoverable: bool,
    pub extensions: Extensions,
}

// Conversion from pure-rust types
impl From<keylib_ctap::types::Credential> for Credential { /* ... */ }
impl From<Credential> for keylib_ctap::types::Credential { /* ... */ }
```

#### 3. Transport Trait (`keylib/src/common/transport.rs`)

```rust
/// Unified transport interface
pub trait Transport {
    fn open(&mut self) -> Result<()>;
    fn close(&mut self);
    fn read(&mut self, buffer: &mut [u8], timeout_ms: i32) -> Result<usize>;
    fn write(&mut self, data: &[u8]) -> Result<()>;
}

/// Unified transport enumeration
pub trait TransportProvider {
    type Transport: Transport;

    fn enumerate() -> Result<Vec<Self::Transport>>;
}
```

#### 4. Client Trait (`keylib/src/common/client.rs`)

```rust
/// Request builders (shared)
pub struct MakeCredentialRequest { /* same as zig-ffi */ }
pub struct GetAssertionRequest { /* same as zig-ffi */ }
pub struct PinUvAuth { /* same as zig-ffi */ }

/// High-level client interface
pub trait Client {
    type Transport: Transport;

    fn make_credential(
        transport: &mut Self::Transport,
        request: MakeCredentialRequest,
    ) -> Result<Vec<u8>>;

    fn get_assertion(
        transport: &mut Self::Transport,
        request: GetAssertionRequest,
    ) -> Result<Vec<u8>>;

    fn authenticator_get_info(
        transport: &mut Self::Transport,
    ) -> Result<Vec<u8>>;
}
```

#### 5. Pure Rust Client Implementation (`keylib/src/rust_impl/client.rs`)

```rust
use crate::common::{Client as ClientTrait, Transport as TransportTrait};

pub struct Client;

impl ClientTrait for Client {
    type Transport = super::transport::Transport;

    fn make_credential(
        transport: &mut Self::Transport,
        request: MakeCredentialRequest,
    ) -> Result<Vec<u8>> {
        // Encode request to CBOR
        let cbor_request = encode_make_credential_request(request)?;

        // Send via transport (CTAP HID)
        let response = transport.send_ctap_command(0x01, &cbor_request)?;

        Ok(response)
    }

    // ... other methods
}
```

#### 6. Pure Rust Transport Implementation (`keylib/src/rust_impl/transport.rs`)

```rust
#[cfg(feature = "usb")]
pub use keylib_transport::usb::UsbTransport;

#[cfg(target_os = "linux")]
pub use keylib_transport::uhid::UhidDevice;

/// Unified transport wrapper for pure Rust
pub enum Transport {
    #[cfg(feature = "usb")]
    Usb(UsbTransport),
    #[cfg(target_os = "linux")]
    Uhid(UhidDevice),
}

impl TransportTrait for Transport {
    fn open(&mut self) -> Result<()> {
        match self {
            #[cfg(feature = "usb")]
            Self::Usb(t) => t.open().map_err(Into::into),
            #[cfg(target_os = "linux")]
            Self::Uhid(t) => t.open().map_err(Into::into),
        }
    }
    // ... other methods
}

pub struct TransportList(Vec<Transport>);

impl TransportList {
    pub fn enumerate() -> Result<Self> {
        let mut transports = Vec::new();

        #[cfg(feature = "usb")]
        {
            let usb_transports = UsbTransport::enumerate()?;
            transports.extend(usb_transports.into_iter().map(Transport::Usb));
        }

        Ok(TransportList(transports))
    }

    pub fn get(&self, index: usize) -> Option<&Transport> {
        self.0.get(index)
    }
}
```

### Test Compatibility Approach

#### Strategy 1: Conditional Compilation (Minimal Changes)

```rust
// keylib/tests/e2e_webauthn_test.rs

#[cfg(feature = "zig-ffi")]
use keylib::{
    Authenticator,
    client::{Client, Transport, TransportList},
    Error, Result,
};

#[cfg(feature = "pure-rust")]
use keylib::{
    rust_impl::authenticator::RustAuthenticator as Authenticator,
    rust_impl::client::Client,
    rust_impl::transport::{Transport, TransportList},
    common::{Error, Result},
};

// Rest of test code unchanged!
#[test]
#[ignore]
fn test_complete_webauthn_flow() -> Result<()> {
    // Same test code for both implementations
    let mut authenticator = Authenticator::start()?;
    let list = TransportList::enumerate()?;
    // ...
}
```

**Pros**: Minimal test changes, maintains implementation separation
**Cons**: Requires careful API alignment, some duplication in imports

#### Strategy 2: Test Helper Abstraction (More Invasive)

```rust
// keylib/tests/common/mod.rs

#[cfg(feature = "zig-ffi")]
pub use keylib::client as client_impl;

#[cfg(feature = "pure-rust")]
pub use keylib::rust_impl::client as client_impl;

pub type Client = client_impl::Client;
pub type Transport = client_impl::Transport;
// ... etc
```

**Pros**: Single import location
**Cons**: More test code changes, less clear which implementation is tested

#### Recommended: Strategy 1 (Conditional Compilation)

This approach:
- Makes it explicit which implementation is being tested
- Requires minimal changes to test code
- Maintains clear separation between implementations
- Allows gradual migration

## Implementation Phases

### Phase 1: Foundation (Unified Types) - **1-2 days**

**Goal**: Create shared type system that both implementations can use.

**Tasks**:
1. Create `keylib/src/common/` module structure
2. Implement `keylib/src/common/error.rs`
   - Define unified `Error` enum
   - Implement `From<StatusCode>` for pure-rust
   - Implement `From<KeylibError>` for zig-ffi (identity conversion)
3. Implement `keylib/src/common/credential.rs`
   - Define unified `Credential`, `CredentialRef`
   - Implement conversions from `keylib_ctap::types::Credential`
   - Keep zig-ffi types as-is
4. Implement `keylib/src/common/client.rs`
   - Move request builders (`MakeCredentialRequest`, `GetAssertionRequest`)
   - Define shared types (`ClientDataHash`, `PinUvAuth`, etc.)
   - No trait yet, just types
5. Update `keylib/src/lib.rs` to re-export common types

**Success Criteria**:
- `cargo build --no-default-features --features zig-ffi` succeeds
- `cargo build --no-default-features --features pure-rust` succeeds
- No breaking changes to existing zig-ffi API

### Phase 2: Transport Layer - **2-3 days**

**Goal**: Expose pure-rust USB HID and UHID transports through unified API.

**Tasks**:
1. Create `keylib/src/rust_impl/transport.rs`
   - Re-export `keylib_transport::usb::UsbTransport` (requires `usb` feature)
   - Re-export `keylib_transport::uhid::UhidDevice` (Linux only)
   - Create `Transport` enum wrapper
   - Create `TransportList` for enumeration
2. Implement unified error conversions for transport errors
3. Add CTAP HID command framing to transport layer
   - Add method: `send_ctap_command(cmd: u8, data: &[u8]) -> Result<Vec<u8>>`
   - Use `CtapHidHandler` internally
4. Write transport unit tests
   - Test USB enumeration (requires USB feature)
   - Test UHID device creation (requires Linux + permissions)

**Success Criteria**:
- `TransportList::enumerate()` works with pure-rust
- Can open/close transports
- Can send/receive CTAP HID messages
- Tests pass: `cargo test -p keylib --features pure-rust,usb`

### Phase 3: Client API - **3-4 days**

**Goal**: Implement high-level `Client` API for pure-rust that matches zig-ffi.

**Tasks**:
1. Create `keylib/src/rust_impl/client.rs`
2. Implement `Client::make_credential()`
   - Build CBOR request from `MakeCredentialRequest`
   - Send command 0x01 via transport
   - Parse CBOR response
   - Return attestation object
3. Implement `Client::get_assertion()`
   - Build CBOR request from `GetAssertionRequest`
   - Send command 0x02 via transport
   - Parse CBOR response
   - Return assertion
4. Implement `Client::authenticator_get_info()`
   - Send command 0x04 via transport
   - Return info response
5. Add comprehensive unit tests
   - Mock transport for request/response testing
   - Test CBOR encoding/decoding

**Success Criteria**:
- Client API compiles with pure-rust
- Unit tests pass
- Can make simple CTAP requests via client

### Phase 4: PIN Protocol Support - **2-3 days**

**Goal**: Add PIN protocol state machine for pure-rust.

**Tasks**:
1. Create `keylib/src/rust_impl/client_pin.rs`
2. Implement `PinUvAuthEncapsulation` wrapper
   - Store protocol version, shared secret, pin token
   - Use `keylib_crypto::pin` primitives
3. Implement key agreement (ECDH)
   - `initialize(transport)` - get authenticator public key
   - Generate shared secret
4. Implement PIN operations
   - `get_pin_uv_auth_token_using_pin_with_permissions()`
   - `set_pin()`
   - `change_pin()`
5. Implement `authenticate()` method for pinUvAuthParam calculation

**Success Criteria**:
- Can perform PIN protocol v2 key agreement
- Can retrieve PIN token with permissions
- Can calculate pinUvAuthParam

### Phase 5: Authenticator Wrapper - **2-3 days**

**Goal**: Align `RustAuthenticator` API with zig-ffi `Authenticator`.

**Tasks**:
1. Update `keylib/src/rust_impl/authenticator.rs`
2. Add `Authenticator::set_pin_hash()` static method
   - Store PIN hash in global state (match zig-ffi behavior)
   - Use for PIN verification in callbacks
3. Add authenticator lifecycle methods
   - `run()` - currently handled by transport layer
   - `stop()` - signal shutdown
4. Align callback signatures
   - Update `BridgeCallbacks` to match zig-ffi callback signatures exactly
   - Add callback wrappers for `read_callback`, `write_callback`, `delete_callback`
5. Integrate with UHID for virtual device
   - Create `Authenticator::start_virtual()` helper
   - Spawn thread running authenticator + UHID device

**Success Criteria**:
- Authenticator API matches zig-ffi
- Can create virtual authenticator with UHID
- Callbacks work with same signatures as zig-ffi

### Phase 6: UHID Integration - **1-2 days**

**Goal**: Expose UHID virtual device through `keylib::rust_impl`.

**Tasks**:
1. Create `keylib/src/rust_impl/uhid.rs` (Linux only)
2. Re-export `keylib_transport::uhid::UhidDevice`
3. Add helper wrapper if needed for error conversion
4. Update error types to handle UHID errors

**Success Criteria**:
- Can create UHID virtual device
- Can read/write UHID events
- Error handling matches zig-ffi `keylib::uhid::Uhid`

### Phase 7: Test Migration - **2-3 days**

**Goal**: Make E2E tests work with both implementations.

**Tasks**:
1. Update `keylib/tests/e2e_webauthn_test.rs`
   - Add conditional imports for zig-ffi vs pure-rust
   - Ensure test logic is implementation-agnostic
   - May need small adjustments for API differences
2. Update `keylib/tests/credential_storage_test.rs`
   - Add pure-rust credential storage tests
   - Use unified credential types
3. Update `keylib/tests/integration.rs`
   - Split into feature-gated sections
   - Add pure-rust integration tests

**Success Criteria**:
- `cargo test --features zig-ffi` passes all tests
- `cargo test --features pure-rust,usb` passes equivalent tests
- E2E WebAuthn flow works with both implementations (on Linux with UHID)

### Phase 8: Documentation & Validation - **1-2 days**

**Goal**: Document the unified interface and validate compatibility.

**Tasks**:
1. Update TESTING_PURE_RUST.md with new interfaces
2. Update examples to support both implementations
3. Add API documentation
   - Document feature flags clearly
   - Show examples for both implementations
4. Run full test suite
   - All unit tests
   - All integration tests
   - E2E tests with both implementations
5. Update CLAUDE.md with new architecture

**Success Criteria**:
- Documentation complete
- All tests pass with both features
- Examples work with both implementations

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1: Foundation | 1-2 days | None |
| Phase 2: Transport Layer | 2-3 days | Phase 1 |
| Phase 3: Client API | 3-4 days | Phase 1, 2 |
| Phase 4: PIN Protocol | 2-3 days | Phase 3 |
| Phase 5: Authenticator Wrapper | 2-3 days | Phase 1, 2 |
| Phase 6: UHID Integration | 1-2 days | Phase 2, 5 |
| Phase 7: Test Migration | 2-3 days | Phase 3, 4, 5, 6 |
| Phase 8: Documentation | 1-2 days | All phases |
| **Total** | **14-22 days** | - |

**Estimated completion**: 3-4 weeks with focused effort

## Success Criteria

### Must Have (Phase 1-7)

1. ✅ **API Compatibility**: Pure-rust exposes same public API as zig-ffi for client operations
2. ✅ **Test Compatibility**: E2E WebAuthn tests pass with both `zig-ffi` and `pure-rust` features
3. ✅ **Transport Support**: USB HID and UHID transports work with pure-rust
4. ✅ **Error Handling**: Unified error types across implementations
5. ✅ **Credential Types**: Unified credential structures
6. ✅ **PIN Protocol**: Full PIN protocol v2 support in pure-rust

### Should Have (Phase 8)

7. ✅ **Documentation**: Comprehensive docs for both implementations
8. ✅ **Examples**: Updated examples showing both implementations
9. ✅ **Performance**: Pure-rust performance comparable to zig-ffi

### Nice to Have (Future)

10. 🔲 **Trait-based abstraction**: Abstract `Client` trait (enables runtime selection)
11. 🔲 **Feature parity**: All zig-ffi features available in pure-rust
12. 🔲 **WASM support**: Pure-rust works in WASM (requires transport abstraction)

## Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| API misalignment breaks tests | High | Medium | Incremental testing, keep zig-ffi tests passing |
| UHID permissions in CI | Medium | High | Document requirements, use feature-gated tests |
| Type conversion overhead | Medium | Low | Use zero-copy where possible, benchmark |
| Breaking changes to zig-ffi | High | Low | Don't modify zig-ffi API, only add common types |
| Timeline overrun | Medium | Medium | Prioritize phases 1-7, phase 8 can be deferred |

## Open Questions

1. **Should we use trait-based abstraction or feature-gated concrete types?**
   - **Recommendation**: Start with feature-gated concrete types (Strategy 1), add traits later if needed
   - **Rationale**: Simpler, faster to implement, no runtime overhead

2. **How to handle platform differences (Linux UHID vs cross-platform USB)?**
   - **Recommendation**: Platform-gated features, graceful degradation
   - **Rationale**: Tests already use `#[ignore]` for platform-specific tests

3. **Should we deprecate zig-ffi once pure-rust is complete?**
   - **Recommendation**: Not immediately, mark as legacy in phase 8
   - **Rationale**: Give users time to migrate, validate pure-rust stability first

4. **What about credential management commands?**
   - **Recommendation**: Include in Phase 3 (Client API)
   - **Rationale**: Same pattern as makeCredential/getAssertion

## Next Steps

1. **Review this plan** - User approval required before implementation
2. **Phase 1 kickoff** - Start with unified error and credential types
3. **Incremental PRs** - Each phase is a separate PR for easier review
4. **Continuous testing** - Run both feature sets in CI after Phase 1

---

**Questions or feedback?** Please review and provide input before implementation begins.

**Branch**: `claude/inspect-rust-implementation-01Whut5rididjbBy2hBxLDWD`
