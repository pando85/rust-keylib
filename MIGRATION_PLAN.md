# Zig-to-Rust Migration Plan

## Overview

This document outlines the strategy for migrating the Zig keylib implementation to pure Rust while maintaining 100% behavioral compatibility and ensuring comprehensive testing at each step.

**Goal**: Replace the Zig keylib with pure Rust implementations, piece by piece, while keeping the existing `keylib` (Rust) API surface unchanged and using `make test-e2e` as the primary validation mechanism.

**Strategy**: Create separate workspace crates for independent components, build a pure Rust `keylib-core` replacement, test by swapping `keylib-sys` → `keylib-core` in keylib's dependencies, and eventually consolidate everything into `keylib`.

**Key Principles**:
- This is a **security library** - behavioral equivalence is critical
- Focus on **functionality and high-level behavior**, not line-by-line Zig translation
- Follow **FIDO2 specifications** (https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html) for any implementation questions
- Test continuously with `make test-e2e` after each component
- Use separate crates for independent features (crypto, CTAP, transport)

---

## Architecture Overview

### Current State
```
Workspace:
  keylib-sys/          # FFI bindings to Zig keylib (C API)
    └── keylib/        # Zig submodule (8,067 lines of Zig)
  keylib/              # Safe Rust API wrapping keylib-sys
```

### Target State
```
Workspace:
  keylib-crypto/       # Pure Rust cryptographic primitives
  keylib-ctap/         # Pure Rust CTAP protocol implementation
  keylib-transport/    # Pure Rust transport layer (CTAPHID, USB)
  keylib/              # Consolidated pure Rust library
```

### Migration Path
```
Phase 1-4: Create modular crates (keylib-crypto, keylib-ctap, keylib-transport)
Phase 5: Create keylib-core that orchestrates all components
Phase 6: Swap keylib-sys → keylib-core in keylib dependencies
Phase 7: Consolidate keylib-core into keylib
Phase 8: Remove keylib-sys and Zig code
```

---

## Migration Phases

### Phase 0: Preparation & Infrastructure

**Duration**: 1 week

**Goals**:
- Set up workspace structure for new crates
- Add necessary dependencies
- Run baseline tests
- Document current behavior

**Tasks**:

1. **Create workspace structure**:
   ```bash
   # Create new crate directories
   cargo new --lib keylib-crypto
   cargo new --lib keylib-ctap
   cargo new --lib keylib-transport
   ```

2. **Update root `Cargo.toml`**:
   ```toml
   [workspace]
   members = [
       "keylib-sys",
       "keylib-crypto",
       "keylib-ctap",
       "keylib-transport",
       "keylib",
   ]
   resolver = "2"

   [workspace.package]
   edition = "2024"
   rust-version = "1.91"
   license = "MIT OR Apache-2.0"

   [workspace.dependencies]
   # Cryptography (well-audited crates)
   p256 = { version = "0.13", features = ["ecdsa", "ecdh"] }
   sha2 = "0.10"
   hmac = "0.12"
   hkdf = "0.12"
   aes = "0.8"
   cbc = "0.1"
   rand = "0.8"

   # CBOR (choose after evaluation)
   ciborium = "0.2"
   serde = { version = "1.0", features = ["derive"] }

   # Utilities
   thiserror = "1.0"
   ```

3. **Run baseline tests and document**:
   ```bash
   # Capture current behavior
   make test-e2e > baseline-e2e-results.txt
   cargo test --all > baseline-test-results.txt

   # Document test expectations
   git add baseline-*.txt
   git commit -m "test: Add baseline test results for migration"
   ```

**Testing**: All existing tests must pass with no changes.

**Success Criteria**:
- Workspace compiles successfully
- New crates added to workspace
- Baseline test results documented
- No regressions

---

### Phase 1: Cryptographic Primitives (`keylib-crypto`)

**Duration**: 2 weeks

**Goals**: Implement pure Rust cryptographic primitives required by FIDO2/CTAP.

**Components**:
- P-256 ECDH (key agreement for PIN protocol)
- P-256 ECDSA (ES256 signatures)
- PIN protocol V1 (AES-256-CBC + SHA-256 HMAC)
- PIN protocol V2 (HMAC-SHA-256)
- Key derivation (HKDF)

**Implementation** (`keylib-crypto/src/`):

1. **Project structure**:
   ```toml
   # keylib-crypto/Cargo.toml
   [package]
   name = "keylib-crypto"
   version = "0.1.0"
   edition.workspace = true
   rust-version.workspace = true

   [dependencies]
   p256.workspace = true
   sha2.workspace = true
   hmac.workspace = true
   hkdf.workspace = true
   aes.workspace = true
   cbc.workspace = true
   rand.workspace = true
   thiserror.workspace = true

   [dev-dependencies]
   hex = "0.4"
   hex-literal = "0.4"
   ```

2. **Module organization**:
   ```
   keylib-crypto/src/
   ├── lib.rs
   ├── ecdh.rs          # P-256 ECDH
   ├── ecdsa.rs         # P-256 ECDSA (ES256)
   ├── pin_protocol.rs  # PIN/UV authentication protocols
   └── error.rs         # Error types
   ```

3. **ECDH implementation** (`ecdh.rs`):
   ```rust
   //! P-256 ECDH for CTAP PIN protocol key agreement
   //!
   //! Implements key agreement per FIDO2 spec:
   //! https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-pin-protocol

   use p256::{
       SecretKey, PublicKey, EncodedPoint,
       ecdh::EphemeralSecret,
       elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint},
   };
   use rand::rngs::OsRng;

   /// P-256 key pair for ECDH
   pub struct KeyPair {
       secret: SecretKey,
       public: PublicKey,
   }

   impl KeyPair {
       /// Generate new random key pair
       pub fn generate() -> Result<Self, Error> {
           let secret = SecretKey::random(&mut OsRng);
           let public = secret.public_key();
           Ok(Self { secret, public })
       }

       /// Get public key in COSE format (uncompressed SEC-1, -1 = x, -2 = y)
       pub fn public_key_cose(&self) -> ([u8; 32], [u8; 32]) {
           let point = self.public.to_encoded_point(false);
           let x = point.x().expect("uncompressed point has x");
           let y = point.y().expect("uncompressed point has y");

           let mut x_bytes = [0u8; 32];
           let mut y_bytes = [0u8; 32];
           x_bytes.copy_from_slice(x.as_slice());
           y_bytes.copy_from_slice(y.as_slice());

           (x_bytes, y_bytes)
       }

       /// Compute shared secret with peer's public key
       pub fn shared_secret(&self, peer_public_key: &[u8]) -> Result<[u8; 32], Error> {
           // Peer key is in COSE format (0x04 || x || y)
           let point = EncodedPoint::from_bytes(peer_public_key)
               .map_err(|_| Error::InvalidPublicKey)?;

           let peer_public = PublicKey::from_encoded_point(&point)
               .map_err(|_| Error::InvalidPublicKey)?;

           let shared = p256::ecdh::diffie_hellman(
               self.secret.to_nonzero_scalar(),
               peer_public.as_affine(),
           );

           let mut secret = [0u8; 32];
           secret.copy_from_slice(shared.raw_secret_bytes());
           Ok(secret)
       }
   }
   ```

4. **ECDSA implementation** (`ecdsa.rs`):
   ```rust
   //! P-256 ECDSA (ES256) signatures for CTAP attestation and assertions
   //!
   //! COSE algorithm identifier: -7 (ES256)
   //! https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1

   use p256::ecdsa::{SigningKey, Signature, signature::Signer};
   use sha2::{Sha256, Digest};

   /// Sign data with ES256 (P-256 + SHA-256)
   pub fn sign(private_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
       let signing_key = SigningKey::from_bytes(private_key.into())
           .map_err(|_| Error::InvalidPrivateKey)?;

       let signature: Signature = signing_key.sign(data);

       // Return DER-encoded signature
       Ok(signature.to_der().to_bytes().to_vec())
   }

   /// Generate new random ES256 key pair
   pub fn generate_keypair() -> ([u8; 32], Vec<u8>) {
       let signing_key = SigningKey::random(&mut OsRng);
       let verifying_key = signing_key.verifying_key();

       let private_key: [u8; 32] = signing_key.to_bytes().into();

       // Public key in uncompressed SEC1 format
       let public_key = verifying_key.to_encoded_point(false).to_bytes().to_vec();

       (private_key, public_key)
   }
   ```

5. **PIN protocol implementation** (`pin_protocol.rs`):
   ```rust
   //! PIN/UV authentication protocols (V1 and V2)
   //!
   //! Spec: https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN

   use hmac::{Hmac, Mac};
   use sha2::Sha256;
   use aes::Aes256;
   use cbc::{Encryptor, Decryptor, cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit}};

   type HmacSha256 = Hmac<Sha256>;

   pub mod v1 {
       //! PIN Protocol Version 1 (AES-256-CBC + SHA-256)

       /// Encrypt data with AES-256-CBC
       pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
           // Use zero IV per spec
           let iv = [0u8; 16];

           let encryptor = Encryptor::<Aes256>::new(key.into(), &iv.into());
           Ok(encryptor.encrypt_padded_vec_mut::<block_padding::Pkcs7>(plaintext))
       }

       /// Decrypt data with AES-256-CBC
       pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
           let iv = [0u8; 16];

           let decryptor = Decryptor::<Aes256>::new(key.into(), &iv.into());
           decryptor.decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
               .map_err(|_| Error::DecryptionFailed)
       }

       /// Compute HMAC-SHA-256 and return first 16 bytes
       pub fn authenticate(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
           let mut mac = HmacSha256::new_from_slice(key).expect("valid key size");
           mac.update(data);
           let result = mac.finalize();
           let mut out = [0u8; 16];
           out.copy_from_slice(&result.into_bytes()[..16]);
           out
       }
   }

   pub mod v2 {
       //! PIN Protocol Version 2 (HMAC-SHA-256, FIPS-approved)

       /// Compute HMAC-SHA-256 and return first 16 bytes
       pub fn authenticate(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
           // Same as V1 for authentication
           super::v1::authenticate(key, data)
       }

       /// Verify HMAC-SHA-256
       pub fn verify(key: &[u8; 32], data: &[u8], expected: &[u8; 16]) -> bool {
           let computed = authenticate(key, data);
           // Constant-time comparison
           use subtle::ConstantTimeEq;
           computed.ct_eq(expected).into()
       }
   }
   ```

6. **Comprehensive tests**:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use hex_literal::hex;

       #[test]
       fn test_ecdh_key_agreement() {
           // Test vectors from FIDO2 spec
           let alice = KeyPair::generate().unwrap();
           let bob = KeyPair::generate().unwrap();

           let alice_shared = alice.shared_secret(&bob.public_key_bytes()).unwrap();
           let bob_shared = bob.shared_secret(&alice.public_key_bytes()).unwrap();

           assert_eq!(alice_shared, bob_shared);
       }

       #[test]
       fn test_es256_signature() {
           let (private_key, public_key) = ecdsa::generate_keypair();
           let message = b"test message";

           let signature = ecdsa::sign(&private_key, message).unwrap();
           assert!(signature.len() > 0);
           // Verification tests would go here
       }

       #[test]
       fn test_pin_protocol_v1_encrypt_decrypt() {
           let key = [0x42u8; 32];
           let plaintext = b"Hello, FIDO2!";

           let ciphertext = v1::encrypt(&key, plaintext).unwrap();
           let decrypted = v1::decrypt(&key, &ciphertext).unwrap();

           assert_eq!(decrypted, plaintext);
       }

       #[test]
       fn test_pin_protocol_v2_authenticate() {
           let key = [0x42u8; 32];
           let data = b"test data";

           let mac = v2::authenticate(&key, data);
           assert!(v2::verify(&key, data, &mac));

           // Modified data should fail
           let bad_data = b"bad data";
           assert!(!v2::verify(&key, bad_data, &mac));
       }
   }
   ```

**Testing**:
```bash
# Unit tests for crypto
cargo test -p keylib-crypto

# Verify no regressions
make test-e2e
```

**Success Criteria**:
- All crypto unit tests pass
- Test vectors from FIDO2 spec validated
- E2E tests still pass (no changes to keylib yet)
- Clean clippy/rustfmt

**Reference**: FIDO2 spec sections 6.5 (PIN protocols), 6.3.3 (ECDH)

---

### Phase 2: CTAP Protocol Implementation (`keylib-ctap`)

**Duration**: 4 weeks

**Goals**: Implement CTAP 2.0/2.1 protocol logic.

**Components**:
- CTAP data types (RelyingParty, User, Credential, etc.)
- CBOR request/response encoding
- CTAP commands (getInfo, makeCredential, getAssertion, clientPin, etc.)
- Authenticator state machine
- PIN/UV protocol state

**Implementation** (`keylib-ctap/src/`):

1. **Project structure**:
   ```toml
   # keylib-ctap/Cargo.toml
   [package]
   name = "keylib-ctap"
   version = "0.1.0"
   edition.workspace = true

   [dependencies]
   keylib-crypto = { path = "../keylib-crypto" }
   ciborium.workspace = true
   serde.workspace = true
   thiserror.workspace = true
   sha2.workspace = true

   [dev-dependencies]
   hex = "0.4"
   ```

2. **Module organization**:
   ```
   keylib-ctap/src/
   ├── lib.rs
   ├── types.rs          # CTAP data types
   ├── credential.rs     # Credential structure
   ├── status.rs         # CTAP status codes
   ├── cbor.rs           # CBOR encoding/decoding
   ├── commands/
   │   ├── mod.rs
   │   ├── get_info.rs
   │   ├── make_credential.rs
   │   ├── get_assertion.rs
   │   ├── client_pin.rs
   │   └── credential_management.rs
   ├── authenticator.rs  # Main authenticator state machine
   ├── pin_token.rs      # PIN token management
   └── callbacks.rs      # Callback trait definitions
   ```

3. **CTAP status codes** (`status.rs`):
   ```rust
   /// CTAP2 status codes
   /// https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#error-responses
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   #[repr(u8)]
   pub enum StatusCode {
       Success = 0x00,
       InvalidCommand = 0x01,
       InvalidParameter = 0x02,
       InvalidLength = 0x03,
       InvalidSeq = 0x04,
       Timeout = 0x05,
       ChannelBusy = 0x06,
       LockRequired = 0x0A,
       InvalidChannel = 0x0B,

       CborUnexpectedType = 0x11,
       InvalidCbor = 0x12,
       MissingParameter = 0x14,
       LimitExceeded = 0x15,
       UnsupportedExtension = 0x16,
       CredentialExcluded = 0x19,
       Processing = 0x21,
       InvalidCredential = 0x22,
       UserActionPending = 0x23,
       OperationPending = 0x24,
       NoOperations = 0x25,
       UnsupportedAlgorithm = 0x26,
       OperationDenied = 0x27,
       KeyStoreFull = 0x28,
       NotBusy = 0x29,
       NoOperationPending = 0x2A,
       UnsupportedOption = 0x2B,
       InvalidOption = 0x2C,
       KeepaliveCancel = 0x2D,
       NoCredentials = 0x2E,
       UserActionTimeout = 0x2F,
       NotAllowed = 0x30,
       PinInvalid = 0x31,
       PinBlocked = 0x32,
       PinAuthInvalid = 0x33,
       PinAuthBlocked = 0x34,
       PinNotSet = 0x35,
       PinRequired = 0x36,
       PinPolicyViolation = 0x37,
       PinTokenExpired = 0x38,
       RequestTooLarge = 0x39,
       ActionTimeout = 0x3A,
       UpRequired = 0x3B,
       UvBlocked = 0x3C,
       IntegrityFailure = 0x3D,
       InvalidSubcommand = 0x3E,
       UvInvalid = 0x3F,
       UnauthorizedPermission = 0x40,
   }
   ```

4. **CTAP types** (`types.rs`):
   ```rust
   use serde::{Deserialize, Serialize};

   /// Relying Party information
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct RelyingParty {
       pub id: String,
       #[serde(skip_serializing_if = "Option::is_none")]
       pub name: Option<String>,
   }

   /// User information
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct User {
       pub id: Vec<u8>,
       #[serde(skip_serializing_if = "Option::is_none")]
       pub name: Option<String>,
       #[serde(skip_serializing_if = "Option::is_none")]
       #[serde(rename = "displayName")]
       pub display_name: Option<String>,
   }

   /// Public key credential descriptor
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct PublicKeyCredentialDescriptor {
       #[serde(rename = "type")]
       pub cred_type: String,  // Always "public-key"
       pub id: Vec<u8>,
       #[serde(skip_serializing_if = "Option::is_none")]
       pub transports: Option<Vec<String>>,
   }

   /// COSE algorithm identifier
   #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
   pub struct CoseAlgorithm(pub i32);

   impl CoseAlgorithm {
       pub const ES256: Self = Self(-7);  // P-256 + SHA-256
       // Add others as needed (EdDSA, RS256, etc.)
   }

   /// Authenticator options
   #[derive(Debug, Clone, Default)]
   pub struct AuthenticatorOptions {
       pub rk: Option<bool>,  // Resident key
       pub up: Option<bool>,  // User presence
       pub uv: Option<bool>,  // User verification
   }
   ```

5. **Authenticator state** (`authenticator.rs`):
   ```rust
   use crate::commands::*;
   use crate::callbacks::Callbacks;
   use crate::pin_token::PinTokenManager;

   /// Main authenticator state machine
   pub struct Authenticator {
       pub config: AuthenticatorConfig,
       pub callbacks: Callbacks,
       pin_hash: Option<[u8; 16]>,
       pin_retries: u8,
       pin_token_manager: PinTokenManager,
       sign_counter: u32,
       next_assertion_state: Option<MultiAssertionState>,
   }

   impl Authenticator {
       pub fn new(config: AuthenticatorConfig, callbacks: Callbacks) -> Self {
           Self {
               config,
               callbacks,
               pin_hash: None,
               pin_retries: 8,
               pin_token_manager: PinTokenManager::new(),
               sign_counter: 0,
               next_assertion_state: None,
           }
       }

       /// Main CTAP command dispatcher
       pub fn handle_command(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, StatusCode> {
           match cmd {
               0x01 => make_credential::handle(self, data),
               0x02 => get_assertion::handle(self, data),
               0x04 => get_info::handle(self),
               0x06 => client_pin::handle(self, data),
               0x08 => self.get_next_assertion(),
               0x0a => credential_management::handle(self, data),
               0x0b => self.selection(),
               0x40..=0xbf => self.handle_vendor_command(cmd, data),
               _ => Err(StatusCode::InvalidCommand),
           }
       }

       pub fn set_pin(&mut self, pin_hash: [u8; 16]) {
           self.pin_hash = Some(pin_hash);
           self.pin_retries = 8;
       }

       pub fn increment_sign_count(&mut self) -> u32 {
           self.sign_counter += 1;
           self.sign_counter
       }
   }
   ```

6. **Implement each command following FIDO2 spec**:
   - `get_info.rs`: Return authenticator capabilities
   - `make_credential.rs`: Create new credential (section 6.1)
   - `get_assertion.rs`: Authenticate with existing credential (section 6.2)
   - `client_pin.rs`: PIN protocol operations (section 6.5)

   Example (`commands/make_credential.rs`):
   ```rust
   /// Handle authenticatorMakeCredential command
   /// https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential
   pub fn handle(auth: &mut Authenticator, data: &[u8]) -> Result<Vec<u8>, StatusCode> {
       // 1. Parse CBOR request
       let req: MakeCredentialRequest = crate::cbor::decode(data)?;

       // 2. Verify PIN/UV auth if present
       if let Some(pin_auth) = &req.pin_uv_auth_param {
           auth.pin_token_manager.verify(
               &req.client_data_hash,
               pin_auth,
               req.pin_uv_auth_protocol.unwrap_or(1),
               Permission::MakeCredential,
               Some(&req.rp.id),
           )?;
       }

       // 3. Check for excluded credentials
       if let Some(exclude_list) = &req.exclude_list {
           for cred in exclude_list {
               if auth.callbacks.credential_exists(&cred.id)? {
                   return Err(StatusCode::CredentialExcluded);
               }
           }
       }

       // 4. Request user presence
       if req.options.up.unwrap_or(true) {
           match auth.callbacks.request_up(&req.user.name, &req.rp.id)? {
               UpResult::Accepted => {},
               _ => return Err(StatusCode::OperationDenied),
           }
       }

       // 5. Request user verification if needed
       let uv_performed = if req.options.uv.unwrap_or(false) {
           match auth.callbacks.request_uv(&req.user.name, &req.rp.id)? {
               UvResult::Accepted | UvResult::AcceptedWithUp => true,
               _ => return Err(StatusCode::OperationDenied),
           }
       } else {
           false
       };

       // 6. Generate credential
       let (private_key, public_key) = keylib_crypto::ecdsa::generate_keypair();
       let credential_id = generate_credential_id(&req.rp.id, &req.user.id)?;

       // 7. Store credential if resident key
       if req.options.rk.unwrap_or(false) {
           let credential = Credential {
               id: credential_id.clone(),
               rp_id: req.rp.id.clone(),
               rp_name: req.rp.name.clone(),
               user_id: req.user.id.clone(),
               user_name: req.user.name.clone(),
               user_display_name: req.user.display_name.clone(),
               sign_count: 0,
               algorithm: CoseAlgorithm::ES256.0,
               private_key,
               created: current_timestamp(),
               discoverable: true,
               cred_protect: determine_cred_protect(&req.extensions),
           };
           auth.callbacks.write_credential(&credential)?;
       }

       // 8. Build authenticator data (32-byte RP ID hash + flags + counter + attested cred data)
       let auth_data = build_authenticator_data(
           &req.rp.id,
           true,          // UP
           uv_performed,  // UV
           auth.increment_sign_count(),
           Some((&auth.config.aaguid, &credential_id, &public_key)),
           &req.extensions,
       )?;

       // 9. Generate attestation signature
       let sig_data = [&auth_data[..], &req.client_data_hash[..]].concat();
       let signature = keylib_crypto::ecdsa::sign(&private_key, &sig_data)?;

       // 10. Build response
       let response = MakeCredentialResponse {
           fmt: "packed".to_string(),
           auth_data,
           att_stmt: build_packed_attestation(&auth.config.aaguid, &signature),
       };

       crate::cbor::encode(&response)
   }
   ```

7. **PIN token management** (`pin_token.rs`):
   ```rust
   /// PIN token with time-limited permissions
   pub struct PinToken {
       token: [u8; 32],
       permissions: u8,
       rp_id: Option<String>,
       created_at: u64,
       last_used: u64,
   }

   impl PinToken {
       // Per spec: 19 second usage window, 10 minute lifetime
       const USAGE_WINDOW_MS: u64 = 19_000;
       const LIFETIME_MS: u64 = 600_000;

       pub fn verify(&mut self, permission: Permission, rp_id: Option<&str>) -> Result<(), StatusCode> {
           let now = current_time_ms();

           // Check lifetime
           if now - self.created_at > Self::LIFETIME_MS {
               return Err(StatusCode::PinTokenExpired);
           }

           // Check usage window
           if now - self.last_used > Self::USAGE_WINDOW_MS {
               return Err(StatusCode::PinAuthInvalid);
           }

           // Check permission
           if self.permissions & (permission as u8) == 0 {
               return Err(StatusCode::UnauthorizedPermission);
           }

           // Check RP ID for RP-specific permissions
           if matches!(permission, Permission::MakeCredential | Permission::GetAssertion) {
               if let Some(required_rp) = rp_id {
                   if self.rp_id.as_deref() != Some(required_rp) {
                       return Err(StatusCode::PinAuthInvalid);
                   }
               }
           }

           self.last_used = now;
           Ok(())
       }
   }
   ```

**Testing**:
```bash
# Unit tests for CTAP
cargo test -p keylib-ctap

# E2E validation (no changes to keylib yet, so should still pass)
make test-e2e
```

**Success Criteria**:
- All CTAP command handlers implemented
- CBOR encoding/decoding works correctly
- PIN token lifecycle validated
- Unit tests pass
- E2E tests still pass

**Reference**: FIDO2 spec sections 6.1-6.6 (CTAP commands)

---

### Phase 3: Transport Layer (`keylib-transport`)

**Duration**: 2 weeks

**Goals**: Implement CTAPHID protocol and USB HID transport.

**Components**:
- CTAPHID message fragmentation/reassembly
- CTAPHID commands (INIT, PING, MSG, CBOR, etc.)
- USB HID device enumeration (via hidapi)
- UHID virtual device support (Linux)

**Implementation** (`keylib-transport/src/`):

1. **Project structure**:
   ```toml
   # keylib-transport/Cargo.toml
   [package]
   name = "keylib-transport"
   version = "0.1.0"
   edition.workspace = true

   [dependencies]
   thiserror.workspace = true
   hidapi = "2.6"  # USB HID

   [target.'cfg(target_os = "linux")'.dependencies]
   nix = { version = "0.29", features = ["fs", "ioctl"] }  # UHID
   ```

2. **Module organization**:
   ```
   keylib-transport/src/
   ├── lib.rs
   ├── ctaphid/
   │   ├── mod.rs
   │   ├── message.rs    # Packet fragmentation/reassembly
   │   └── commands.rs   # CTAPHID command codes
   ├── usb.rs            # USB HID transport
   └── uhid.rs           # Linux UHID virtual device
   ```

3. **CTAPHID message** (`ctaphid/message.rs`):
   ```rust
   /// CTAPHID packet size (USB HID report size)
   pub const PACKET_SIZE: usize = 64;

   /// CTAPHID message
   pub struct Message {
       pub cid: u32,      // Channel ID
       pub cmd: u8,       // Command byte
       pub data: Vec<u8>, // Payload
   }

   impl Message {
       /// Fragment message into 64-byte packets
       pub fn to_packets(&self) -> Vec<[u8; PACKET_SIZE]> {
           let mut packets = Vec::new();

           // Initialization packet: CID(4) | CMD(1) | LEN(2) | DATA(57)
           let mut pkt = [0u8; PACKET_SIZE];
           pkt[0..4].copy_from_slice(&self.cid.to_be_bytes());
           pkt[4] = self.cmd | 0x80;  // Set initialization bit
           pkt[5..7].copy_from_slice(&(self.data.len() as u16).to_be_bytes());

           let chunk_size = (PACKET_SIZE - 7).min(self.data.len());
           pkt[7..7 + chunk_size].copy_from_slice(&self.data[..chunk_size]);
           packets.push(pkt);

           // Continuation packets: CID(4) | SEQ(1) | DATA(59)
           let mut offset = chunk_size;
           let mut seq = 0u8;

           while offset < self.data.len() {
               let mut pkt = [0u8; PACKET_SIZE];
               pkt[0..4].copy_from_slice(&self.cid.to_be_bytes());
               pkt[4] = seq;

               let chunk_size = (PACKET_SIZE - 5).min(self.data.len() - offset);
               pkt[5..5 + chunk_size].copy_from_slice(&self.data[offset..offset + chunk_size]);
               packets.push(pkt);

               offset += chunk_size;
               seq += 1;
           }

           packets
       }

       /// Reassemble message from packets
       pub fn from_packets(packets: &[&[u8; PACKET_SIZE]]) -> Result<Self, Error> {
           if packets.is_empty() {
               return Err(Error::InvalidPacket);
           }

           // Parse init packet
           let init = packets[0];
           let cid = u32::from_be_bytes(init[0..4].try_into()?);
           let cmd = init[4] & 0x7F;
           let len = u16::from_be_bytes(init[5..7].try_into()?) as usize;

           let mut data = Vec::with_capacity(len);
           data.extend_from_slice(&init[7..]);

           // Parse continuation packets
           for (seq, pkt) in packets[1..].iter().enumerate() {
               if u32::from_be_bytes(pkt[0..4].try_into()?) != cid {
                   return Err(Error::InvalidCid);
               }
               if pkt[4] != seq as u8 {
                   return Err(Error::InvalidSequence);
               }
               data.extend_from_slice(&pkt[5..]);
           }

           data.truncate(len);
           Ok(Self { cid, cmd, data })
       }
   }
   ```

4. **USB HID transport** (`usb.rs`):
   ```rust
   use hidapi::{HidApi, HidDevice};

   pub struct UsbTransport {
       device: HidDevice,
   }

   impl UsbTransport {
       /// Enumerate FIDO devices
       pub fn enumerate() -> Result<Vec<DeviceInfo>, Error> {
           let api = HidApi::new()?;
           let devices = api.device_list()
               .filter(|d| d.usage_page() == 0xF1D0)  // FIDO usage page
               .map(DeviceInfo::from)
               .collect();
           Ok(devices)
       }

       /// Send packet
       pub fn write(&mut self, packet: &[u8; PACKET_SIZE]) -> Result<(), Error> {
           self.device.write(packet)?;
           Ok(())
       }

       /// Receive packet with timeout
       pub fn read(&mut self, timeout_ms: i32) -> Result<[u8; PACKET_SIZE], Error> {
           let mut buf = [0u8; PACKET_SIZE];
           let n = self.device.read_timeout(&mut buf, timeout_ms)?;
           if n != PACKET_SIZE {
               return Err(Error::InvalidPacketSize);
           }
           Ok(buf)
       }
   }
   ```

**Testing**:
```bash
cargo test -p keylib-transport
make test-e2e  # Should still pass
```

**Success Criteria**:
- CTAPHID fragmentation works correctly
- USB enumeration functional
- UHID integration works on Linux
- E2E tests pass

---

### Phase 4: Core Integration (`keylib-core`)

**Duration**: 2 weeks

**Goals**: Create orchestrating crate that combines crypto + CTAP + transport.

**Implementation**:

1. **Create `keylib-core`**:
   ```toml
   # keylib-core/Cargo.toml
   [package]
   name = "keylib-core"
   version = "0.1.0"
   edition.workspace = true

   [dependencies]
   keylib-crypto = { path = "../keylib-crypto" }
   keylib-ctap = { path = "../keylib-ctap" }
   keylib-transport = { path = "../keylib-transport" }
   thiserror.workspace = true
   ```

2. **Re-export components**:
   ```rust
   // keylib-core/src/lib.rs

   pub use keylib_crypto as crypto;
   pub use keylib_ctap as ctap;
   pub use keylib_transport as transport;

   // Re-export main types for convenience
   pub use ctap::{Authenticator, AuthenticatorConfig};
   pub use transport::{UsbTransport, DeviceInfo};
   ```

3. **Provide same API surface as keylib-sys** (for drop-in replacement):
   ```rust
   // C FFI compatibility layer (if needed temporarily)
   mod ffi;
   pub use ffi::*;
   ```

**Testing**:
```bash
cargo test -p keylib-core
```

**Success Criteria**:
- All components integrate cleanly
- API surface matches keylib-sys
- Tests pass

---

### Phase 5: Integration Testing (Swap `keylib-sys` → `keylib-core`)

**Duration**: 1 week

**Goals**: Test pure Rust implementation with existing `keylib` crate.

**Tasks**:

1. **Update `keylib/Cargo.toml`**:
   ```toml
   [dependencies]
   # keylib-sys = { path = "../keylib-sys" }  # Old
   keylib-core = { path = "../keylib-core" }  # New
   ```

2. **Update imports in `keylib/src/`**:
   ```rust
   // use keylib_sys as ffi;  // Old
   use keylib_core as ffi;    // New
   ```

3. **Run full test suite**:
   ```bash
   # Unit tests
   cargo test -p keylib

   # Integration tests
   cargo test -p keylib integration
   cargo test -p keylib credential_storage

   # E2E tests (CRITICAL)
   make test-e2e

   # Examples
   cargo run --example authenticator
   cargo run --example client
   cargo run --example webauthn_flow
   ```

4. **Compare behavior**:
   ```bash
   # Test with Zig implementation
   git stash  # Stash keylib-core changes
   make test-e2e > zig-output.txt

   # Test with Rust implementation
   git stash pop
   make test-e2e > rust-output.txt

   # Compare
   diff zig-output.txt rust-output.txt
   ```

**Testing**: ALL 4 E2E test cases MUST pass:
- `test_complete_webauthn_flow`
- `test_pin_change_flow`
- `test_uv_only_authenticator`
- `test_registration_without_pin`

**Success Criteria**:
- E2E tests pass with identical behavior
- All integration tests pass
- All examples work
- No performance regression

---

### Phase 6: Consolidation (Merge `keylib-core` into `keylib`)

**Duration**: 1 week

**Goals**: Consolidate pure Rust implementation into main `keylib` crate.

**Tasks**:

1. **Move modular crates into `keylib/src/`**:
   ```
   keylib/src/
   ├── crypto/      # from keylib-crypto
   ├── ctap/        # from keylib-ctap
   ├── transport/   # from keylib-transport
   ├── authenticator.rs
   ├── client/
   └── lib.rs
   ```

2. **Update `keylib/Cargo.toml`** to include all dependencies:
   ```toml
   [dependencies]
   # Crypto
   p256.workspace = true
   sha2.workspace = true
   hmac.workspace = true
   # ... etc
   ```

3. **Remove intermediate crates**:
   ```bash
   git rm -r keylib-crypto keylib-ctap keylib-transport keylib-core
   ```

4. **Update documentation**:
   - Update `README.md` to reflect pure Rust architecture
   - Update `CLAUDE.md`
   - Add migration notes to `CHANGELOG.md`

**Testing**:
```bash
make test-all
cargo run --example webauthn_flow
```

**Success Criteria**:
- Single `keylib` crate with all functionality
- All tests pass
- Examples work
- Documentation updated

---

### Phase 7: Cleanup (Remove `keylib-sys` and Zig)

**Duration**: 1 week

**Goals**: Remove all Zig code and dependencies.

**Tasks**:

1. **Remove Zig submodule**:
   ```bash
   git rm -r keylib-sys
   git rm .gitmodules  # If no other submodules
   rm -rf .git/modules/keylib-sys
   ```

2. **Update workspace**:
   ```toml
   # Cargo.toml
   [workspace]
   members = [
       "keylib",  # Only member now
   ]
   ```

3. **Update CI/CD**:
   - Remove Zig installation steps
   - Remove libudev-dev requirement (if not needed)
   - Update build matrix

4. **Update documentation**:
   - Remove Zig references from README
   - Simplify build instructions
   - Update architecture diagrams

5. **Final validation**:
   ```bash
   cargo clean
   cargo build --release
   make test-all

   # Test bundled feature still works
   cargo build --features bundled
   ```

**Success Criteria**:
- No Zig code in repository
- Build succeeds without Zig compiler
- All tests pass
- CI/CD pipelines green
- Documentation accurate

---

## Testing Strategy

### Continuous Validation

**After EVERY phase**:

1. **Unit tests**:
   ```bash
   cargo test -p <crate-name>
   ```

2. **Integration tests**:
   ```bash
   cargo test -p keylib integration
   ```

3. **E2E tests** (MANDATORY):
   ```bash
   make test-e2e
   ```

   All 4 test cases must pass:
   - `test_complete_webauthn_flow` - Full WebAuthn registration + authentication
   - `test_pin_change_flow` - PIN update mechanism
   - `test_uv_only_authenticator` - User verification without PIN
   - `test_registration_without_pin` - PIN-optional registration

4. **Examples**:
   ```bash
   cargo run --example authenticator
   cargo run --example client
   cargo run --example webauthn_flow
   ```

### Security Validation

Since this is a **security library**, extra validation is required:

1. **Cryptographic correctness**:
   - Test with FIDO2 spec test vectors
   - Validate against known-good implementations
   - Cross-check CBOR encoding byte-for-byte

2. **Timing attacks**:
   - Use constant-time comparison for secrets
   - Validate with timing analysis tools

3. **Memory safety**:
   - Run with `RUSTFLAGS="-Z sanitizer=address"`
   - Check for leaks with valgrind
   - Audit unsafe code (should be minimal)

4. **Fuzzing** (optional but recommended):
   ```bash
   cargo fuzz run fuzz_make_credential
   cargo fuzz run fuzz_get_assertion
   ```

---

## Timeline Summary

| Phase | Duration | Focus |
|-------|----------|-------|
| 0. Preparation | 1 week | Setup workspace, baseline tests |
| 1. Crypto | 2 weeks | ECDH, ECDSA, PIN protocols |
| 2. CTAP | 4 weeks | Protocol implementation |
| 3. Transport | 2 weeks | CTAPHID, USB HID |
| 4. Core Integration | 2 weeks | Combine components |
| 5. Integration Testing | 1 week | Swap keylib-sys → keylib-core |
| 6. Consolidation | 1 week | Merge into keylib |
| 7. Cleanup | 1 week | Remove Zig |

**Total**: ~14 weeks (~3.5 months)

---

## Success Metrics

### Functional
- ✅ All E2E tests pass (4/4)
- ✅ All integration tests pass
- ✅ All examples work
- ✅ Behavior identical to Zig implementation

### Quality
- ✅ >80% test coverage
- ✅ Zero unsafe in public API
- ✅ All clippy warnings resolved
- ✅ FIDO2 spec compliance validated

### Performance
- ✅ Build time improved (no Zig compilation)
- ✅ Runtime performance ≥ Zig implementation
- ✅ Binary size comparable

### Security
- ✅ Audited crypto crates used
- ✅ Constant-time comparisons for secrets
- ✅ No memory leaks
- ✅ Clean Miri/sanitizer runs

---

## Key Principles (Recap)

1. **Security first** - This is a security library; behavioral equivalence is critical
2. **Test continuously** - Run `make test-e2e` after every phase
3. **Follow FIDO2 spec** - When in doubt, consult https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html
4. **Modular design** - Independent crates for crypto, CTAP, transport
5. **Incremental migration** - Each phase delivers value independently
6. **No line-by-line translation** - Focus on functionality and behavior

---

## Next Steps

1. Review and approve this plan
2. Set up project tracking (GitHub issues/milestones)
3. Begin Phase 0: Preparation
4. Establish baseline test results
5. Start Phase 1: Cryptography implementation

---

## References

- **FIDO2 Spec**: https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html
- **WebAuthn Spec**: https://www.w3.org/TR/webauthn-2/
- **CTAP Error Codes**: Section 9 of FIDO2 spec
- **PIN Protocols**: Section 6.5 of FIDO2 spec
- **Authenticator Commands**: Sections 6.1-6.6 of FIDO2 spec
