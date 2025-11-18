# API Compatibility Plan: Unified zig-ffi and pure-rust Interface

## Goal

Make the zig-ffi and pure-rust implementations API-compatible so the same test code works with both, enabling transparent feature flag switching.

## Current API Gaps

### 1. Authenticator Configuration

**zig-ffi**:
- `AuthenticatorOptions` - detailed capability flags (rk, uv, client_pin, cred_mgmt, etc.)
- `CtapCommand` enum - list of supported commands
- `AuthenticatorConfig::builder().commands(vec![...]).options(...)`

**pure-rust**:
- Simplified `AuthenticatorConfig` with just aaguid, max_credentials, extensions
- No command configuration
- No detailed options

**Fix**: Add `AuthenticatorOptions` and `CtapCommand` to pure-rust, make them no-ops.

### 2. Callbacks API

**zig-ffi**:
```rust
Callbacks::new(
    up_callback,
    uv_callback,
    select_callback,
    read_callback,
    write_callback,
    delete_callback,
    read_first_callback,
    read_next_callback,
)
```

**pure-rust**:
```rust
CallbacksBuilder::new()
    .up(...)
    .uv(...)
    .build()
```

**Fix**: Add `Callbacks::new()` constructor to pure-rust matching zig-ffi signature.

### 3. CTAP HID Protocol

**zig-ffi**:
- `Ctaphid` type for manual protocol handling
- Tests manually manage CTAP HID framing

**pure-rust**:
- No `Ctaphid` type exposed
- Uses internal `Message`/`Packet` from keylib-transport

**Fix**: Export `Ctaphid`-compatible type from pure-rust or adapt tests to not use it.

### 4. Type Exports

**zig-ffi** exports at root: `keylib::Authenticator`, `keylib::Callbacks`, etc.

**pure-rust** exports under `keylib::rust_impl::*`

**Fix**: Re-export pure-rust types at root level when pure-rust feature is active.

## Implementation Plan

### Phase 1: Add Missing Types to pure-rust

1. **Create `CtapCommand` enum** (no-op, for API compat):
   ```rust
   // In keylib/src/rust_impl/authenticator.rs
   pub enum CtapCommand {
       MakeCredential,
       GetAssertion,
       GetInfo,
       ClientPin,
       CredentialManagement,
       Selection,
   }
   ```

2. **Create `AuthenticatorOptions` struct**:
   ```rust
   pub struct AuthenticatorOptions {
       // Fields match zig-ffi but are mostly ignored in pure-rust
   }
   ```

3. **Update `AuthenticatorConfig`** to accept commands and options:
   ```rust
   pub struct AuthenticatorConfig {
       aaguid: [u8; 16],
       commands: Vec<CtapCommand>,  // New
       options: AuthenticatorOptions,  // New
       max_credentials: usize,
       extensions: Vec<String>,
   }
   ```

### Phase 2: Unify Callbacks API

1. **Add `Callbacks::new()` constructor**:
   ```rust
   impl Callbacks {
       pub fn new(
           up: Option<UpCallback>,
           uv: Option<UvCallback>,
           select: Option<SelectCallback>,
           read: Option<ReadCallback>,
           write: Option<WriteCallback>,
           delete: Option<DeleteCallback>,
           read_first: Option<ReadFirstCallback>,
           read_next: Option<ReadNextCallback>,
       ) -> Self {
           Self { up, uv, select, write, delete, ... }
       }
   }
   ```

2. **Add read/read_first/read_next callbacks** to match zig-ffi:
   - Currently pure-rust uses `read_credentials` and `get_credential`
   - Zig-ffi uses `read`, `read_first`, `read_next`
   - Make pure-rust support both APIs

### Phase 3: Export Unified Types

1. **Update `keylib/src/lib.rs`** to re-export pure-rust types at root:
   ```rust
   // When pure-rust is enabled, export at root level
   #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
   pub use rust_impl::authenticator::{
       Authenticator, AuthenticatorConfig, AuthenticatorOptions,
       Callbacks, CtapCommand, UpResult, UvResult,
   };
   #[cfg(all(feature = "pure-rust", not(feature = "zig-ffi")))]
   pub use rust_impl::client::Client;
   // etc.
   ```

2. **Re-export common types** for both:
   ```rust
   // Always available via common module
   pub use common::{
       Credential, CredentialRef, RelyingParty, User,
       ClientDataHash, Error, Result,
   };
   ```

### Phase 4: Optional - Ctaphid Compatibility

**Option A**: Don't expose `Ctaphid`, refactor tests to not use it
- Tests use higher-level Transport API instead
- Simpler, less zig-ffi baggage

**Option B**: Create `Ctaphid` wrapper in pure-rust
- Wraps `Message`/`Packet` from keylib-transport
- More work, maintains exact compat

**Recommendation**: Option A - refactor tests

### Phase 5: Test Unification

1. **Update imports** in `e2e_webauthn_test.rs`:
   ```rust
   // Remove feature gates - use unified imports
   use keylib::{
       Authenticator, AuthenticatorConfig, AuthenticatorOptions,
       Callbacks, CtapCommand, UpResult, UvResult,
       Client, ClientDataHash, GetAssertionRequest,
       MakeCredentialRequest, PinUvAuth, PinUvAuthProtocol,
       TransportList, User, RelyingParty, Uhid,
   };
   use keylib::client_pin::{PinProtocol, PinUvAuthEncapsulation};
   ```

2. **Adapt test implementation** to work with both:
   - Remove `Ctaphid` usage
   - Use Transport API directly
   - Use unified callback API

## Timeline Estimate

- Phase 1: Add missing types (~30 min)
- Phase 2: Unify callbacks (~20 min)
- Phase 3: Export types (~15 min)
- Phase 4: Skip (refactor tests instead) (~10 min)
- Phase 5: Test unification (~30 min)

**Total**: ~1.5 hours

## Success Criteria

1. ✅ `cargo test --test e2e_webauthn_test --features zig-ffi -- --ignored` passes
2. ✅ `cargo test --test e2e_webauthn_test --features pure-rust -- --ignored` passes
3. ✅ Same test file works with both features
4. ✅ API documented and consistent
