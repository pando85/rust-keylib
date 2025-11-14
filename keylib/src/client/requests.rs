//! Request builders for CTAP2 client operations

use super::types::{ClientDataHash, CredentialDescriptor, PinUvAuth};

use crate::client::User;
use crate::credential::RelyingParty;

/// Request for creating a new credential (authenticatorMakeCredential)
///
/// Use the builder pattern to construct requests with optional parameters.
///
/// # Example
///
/// ```no_run
/// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User, PinUvAuth, PinUvAuthProtocol};
/// # use keylib::credential::RelyingParty;
/// # use keylib::Result;
/// # fn example() -> Result<()> {
/// let hash = ClientDataHash::new([0u8; 32]);
/// let rp = RelyingParty {
///     id: "example.com".to_string(),
///     name: Some("Example Corp".to_string()),
/// };
/// let user = User {
///     id: vec![1, 2, 3, 4],
///     name: "alice@example.com".to_string(),
///     display_name: Some("Alice".to_string()),
/// };
///
/// let request = MakeCredentialRequest::new(hash, rp, user)
///     .with_timeout(60000);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MakeCredentialRequest {
    pub(crate) client_data_hash: ClientDataHash,
    pub(crate) rp: RelyingParty,
    pub(crate) user: User,
    pub(crate) pin_uv_auth: Option<PinUvAuth>,
    pub(crate) timeout_ms: i32,
    pub(crate) resident_key: Option<bool>,
    pub(crate) user_verification: Option<bool>,
}

impl MakeCredentialRequest {
    /// Create a new MakeCredentialRequest with required parameters
    ///
    /// # Arguments
    ///
    /// * `client_data_hash` - SHA-256 hash of the WebAuthn client data
    /// * `rp` - Relying party information (ID and optional name)
    /// * `user` - User information (ID, name, optional display name)
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User, PinUvAuth, PinUvAuthProtocol};
    /// # use keylib::credential::RelyingParty;
    /// let hash = ClientDataHash::new([0u8; 32]);
    /// let rp = RelyingParty {
    ///     id: "example.com".to_string(),
    ///     name: Some("Example Corp".to_string()),
    /// };
    /// let user = User {
    ///     id: vec![1, 2, 3, 4],
    ///     name: "alice@example.com".to_string(),
    ///     display_name: Some("Alice".to_string()),
    /// };
    ///
    /// let request = MakeCredentialRequest::new(hash, rp, user);
    /// ```
    pub fn new(client_data_hash: ClientDataHash, rp: RelyingParty, user: User) -> Self {
        Self {
            client_data_hash,
            rp,
            user,
            pin_uv_auth: None,
            timeout_ms: 30000, // 30 second default
            resident_key: None,
            user_verification: None,
        }
    }

    /// Set the PIN/UV authentication parameter
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User, PinUvAuth, PinUvAuthProtocol};
    /// # use keylib::credential::RelyingParty;
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// # let rp = RelyingParty { id: "example.com".to_string(), name: None };
    /// # let user = User { id: vec![1], name: "alice".to_string(), display_name: None };
    /// let pin_auth = PinUvAuth::new(vec![1, 2, 3, 4], PinUvAuthProtocol::V2);
    /// let request = MakeCredentialRequest::new(hash, rp, user)
    ///     .with_pin_uv_auth(pin_auth);
    /// ```
    pub fn with_pin_uv_auth(mut self, auth: PinUvAuth) -> Self {
        self.pin_uv_auth = Some(auth);
        self
    }

    /// Set the timeout in milliseconds
    ///
    /// Default is 30000ms (30 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User};
    /// # use keylib::credential::RelyingParty;
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// # let rp = RelyingParty { id: "example.com".to_string(), name: None };
    /// # let user = User { id: vec![1], name: "alice".to_string(), display_name: None };
    /// let request = MakeCredentialRequest::new(hash, rp, user)
    ///     .with_timeout(60000); // 60 seconds
    /// ```
    pub fn with_timeout(mut self, timeout_ms: i32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set whether to create a resident key (discoverable credential)
    ///
    /// When set to `true`, the credential will be stored on the authenticator
    /// and can be discovered without providing a credential ID.
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User};
    /// # use keylib::credential::RelyingParty;
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// # let rp = RelyingParty { id: "example.com".to_string(), name: None };
    /// # let user = User { id: vec![1], name: "alice".to_string(), display_name: None };
    /// let request = MakeCredentialRequest::new(hash, rp, user)
    ///     .with_resident_key(true);
    /// ```
    pub fn with_resident_key(mut self, resident_key: bool) -> Self {
        self.resident_key = Some(resident_key);
        self
    }

    /// Set whether to require user verification
    ///
    /// When set to `true`, the authenticator must perform user verification
    /// (e.g., biometric check, PIN entry). This is required for UV-only
    /// authenticators (those without PIN set).
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{MakeCredentialRequest, ClientDataHash, User};
    /// # use keylib::credential::RelyingParty;
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// # let rp = RelyingParty { id: "example.com".to_string(), name: None };
    /// # let user = User { id: vec![1], name: "alice".to_string(), display_name: None };
    /// let request = MakeCredentialRequest::new(hash, rp, user)
    ///     .with_user_verification(true);
    /// ```
    pub fn with_user_verification(mut self, user_verification: bool) -> Self {
        self.user_verification = Some(user_verification);
        self
    }

    /// Get the client data hash
    pub fn client_data_hash(&self) -> &ClientDataHash {
        &self.client_data_hash
    }

    /// Get the relying party information
    pub fn rp(&self) -> &RelyingParty {
        &self.rp
    }

    /// Get the user information
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Get the PIN/UV authentication parameter if set
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the timeout in milliseconds
    pub fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }
}

/// Request for getting an assertion (authenticatorGetAssertion)
///
/// Use the builder pattern to construct requests with optional parameters.
///
/// # Example
///
/// ```no_run
/// # use keylib::client::{GetAssertionRequest, ClientDataHash, CredentialDescriptor, PinUvAuth, PinUvAuthProtocol};
/// # use keylib::Result;
/// # fn example() -> Result<()> {
/// let hash = ClientDataHash::new([0u8; 32]);
///
/// let request = GetAssertionRequest::new(hash, "example.com")
///     .with_timeout(60000);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct GetAssertionRequest {
    pub(crate) client_data_hash: ClientDataHash,
    pub(crate) rp_id: String,
    pub(crate) allow_list: Vec<CredentialDescriptor>,
    pub(crate) pin_uv_auth: Option<PinUvAuth>,
    pub(crate) timeout_ms: i32,
    pub(crate) user_verification: Option<bool>,
}

impl GetAssertionRequest {
    /// Create a new GetAssertionRequest with required parameters
    ///
    /// # Arguments
    ///
    /// * `client_data_hash` - SHA-256 hash of the WebAuthn client data
    /// * `rp_id` - Relying party identifier (domain)
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash};
    /// let hash = ClientDataHash::new([0u8; 32]);
    /// let request = GetAssertionRequest::new(hash, "example.com");
    /// ```
    pub fn new(client_data_hash: ClientDataHash, rp_id: impl Into<String>) -> Self {
        Self {
            client_data_hash,
            rp_id: rp_id.into(),
            allow_list: Vec::new(),
            pin_uv_auth: None,
            timeout_ms: 30000, // 30 second default
            user_verification: None,
        }
    }

    /// Add a single credential to the allow list
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash, CredentialDescriptor};
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// let credential = CredentialDescriptor::public_key(vec![1, 2, 3, 4]);
    /// let request = GetAssertionRequest::new(hash, "example.com")
    ///     .with_credential(credential);
    /// ```
    pub fn with_credential(mut self, credential: CredentialDescriptor) -> Self {
        self.allow_list.push(credential);
        self
    }

    /// Set the allow list to a specific set of credentials
    ///
    /// This replaces any credentials previously added with `with_credential`.
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash, CredentialDescriptor};
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// let credentials = vec![
    ///     CredentialDescriptor::public_key(vec![1, 2, 3, 4]),
    ///     CredentialDescriptor::public_key(vec![5, 6, 7, 8]),
    /// ];
    /// let request = GetAssertionRequest::new(hash, "example.com")
    ///     .with_credentials(credentials);
    /// ```
    pub fn with_credentials(mut self, credentials: Vec<CredentialDescriptor>) -> Self {
        self.allow_list = credentials;
        self
    }

    /// Set the PIN/UV authentication parameter
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash, PinUvAuth, PinUvAuthProtocol};
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// let pin_auth = PinUvAuth::new(vec![1, 2, 3, 4], PinUvAuthProtocol::V2);
    /// let request = GetAssertionRequest::new(hash, "example.com")
    ///     .with_pin_uv_auth(pin_auth);
    /// ```
    pub fn with_pin_uv_auth(mut self, auth: PinUvAuth) -> Self {
        self.pin_uv_auth = Some(auth);
        self
    }

    /// Set the timeout in milliseconds
    ///
    /// Default is 30000ms (30 seconds).
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash};
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// let request = GetAssertionRequest::new(hash, "example.com")
    ///     .with_timeout(60000); // 60 seconds
    /// ```
    pub fn with_timeout(mut self, timeout_ms: i32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set whether to require user verification
    ///
    /// When set to `true`, the authenticator must perform user verification
    /// (e.g., biometric check, PIN entry). This is required for UV-only
    /// authenticators (those without PIN set).
    ///
    /// # Example
    ///
    /// ```
    /// # use keylib::client::{GetAssertionRequest, ClientDataHash};
    /// # let hash = ClientDataHash::new([0u8; 32]);
    /// let request = GetAssertionRequest::new(hash, "example.com")
    ///     .with_user_verification(true);
    /// ```
    pub fn with_user_verification(mut self, user_verification: bool) -> Self {
        self.user_verification = Some(user_verification);
        self
    }

    /// Get the client data hash
    pub fn client_data_hash(&self) -> &ClientDataHash {
        &self.client_data_hash
    }

    /// Get the relying party identifier
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Get the allow list of credentials
    pub fn allow_list(&self) -> &[CredentialDescriptor] {
        &self.allow_list
    }

    /// Get the PIN/UV authentication parameter if set
    pub fn pin_uv_auth(&self) -> Option<&PinUvAuth> {
        self.pin_uv_auth.as_ref()
    }

    /// Get the timeout in milliseconds
    pub fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }
}
