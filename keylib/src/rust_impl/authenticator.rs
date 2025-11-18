//! Pure Rust Authenticator Implementation
//!
//! Provides a high-level interface to the pure Rust CTAP authenticator.

#[cfg(feature = "pure-rust")]
use keylib_ctap::{
    authenticator::{Authenticator as CtapAuthenticator, AuthenticatorConfig as CtapConfig},
    callbacks::{
        CredentialStorageCallbacks, UserInteractionCallbacks, UpResult,
        UvResult,
    },
    types::Credential,
    StatusCode,
};



#[cfg(all(feature = "pure-rust", feature = "usb"))]
use keylib_transport::AuthenticatorRunner;

#[cfg(feature = "pure-rust")]
use std::collections::HashMap;
#[cfg(feature = "pure-rust")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "pure-rust")]
type Result<T> = std::result::Result<T, StatusCode>;

/// Wrapper callbacks that bridge to the existing keylib callback interface
#[cfg(feature = "pure-rust")]
pub struct BridgeCallbacks {
    // Credential storage
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,

    // User interaction callbacks
    up_callback: Option<Arc<dyn Fn(&str, Option<&str>, &str) -> Result<UpResult> + Send + Sync>>,
    uv_callback: Option<Arc<dyn Fn(&str, Option<&str>, &str) -> Result<UvResult> + Send + Sync>>,
}

#[cfg(feature = "pure-rust")]
impl Default for BridgeCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeCallbacks {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(Mutex::new(HashMap::new())),
            up_callback: None,
            uv_callback: None,
        }
    }

    pub fn with_up_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, Option<&str>, &str) -> Result<UpResult> + Send + Sync + 'static,
    {
        self.up_callback = Some(Arc::new(callback));
        self
    }

    pub fn with_uv_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, Option<&str>, &str) -> Result<UvResult> + Send + Sync + 'static,
    {
        self.uv_callback = Some(Arc::new(callback));
        self
    }
}

#[cfg(feature = "pure-rust")]
impl UserInteractionCallbacks for BridgeCallbacks {
    fn request_up(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UpResult> {
        if let Some(callback) = &self.up_callback {
            callback(info, user_name, rp_id)
        } else {
            // Default: auto-approve
            Ok(UpResult::Accepted)
        }
    }

    fn request_uv(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UvResult> {
        if let Some(callback) = &self.uv_callback {
            callback(info, user_name, rp_id)
        } else {
            // Default: auto-approve
            Ok(UvResult::Accepted)
        }
    }

    fn select_credential(&self, _rp_id: &str, _user_names: &[String]) -> Result<usize> {
        // Default: select first credential
        Ok(0)
    }
}

#[cfg(feature = "pure-rust")]
impl CredentialStorageCallbacks for BridgeCallbacks {
    fn write_credential(&self, credential: &Credential) -> Result<()> {
        let mut storage = self.credentials.lock().unwrap();
        storage.insert(credential.id.clone(), credential.clone());
        Ok(())
    }

    fn delete_credential(&self, credential_id: &[u8]) -> Result<()> {
        let mut storage = self.credentials.lock().unwrap();
        storage.remove(credential_id);
        Ok(())
    }

    fn read_credentials(
        &self,
        rp_id: &str,
        user_id: Option<&[u8]>,
    ) -> Result<Vec<Credential>> {
        let storage = self.credentials.lock().unwrap();
        let creds: Vec<Credential> = storage
            .values()
            .filter(|c| {
                c.rp_id == rp_id
                    && (user_id.is_none() || user_id == Some(c.user_id.as_slice()))
            })
            .cloned()
            .collect();
        Ok(creds)
    }

    fn credential_exists(&self, credential_id: &[u8]) -> Result<bool> {
        let storage = self.credentials.lock().unwrap();
        Ok(storage.contains_key(credential_id))
    }

    fn get_credential(&self, credential_id: &[u8]) -> Result<Credential> {
        let storage = self.credentials.lock().unwrap();
        storage
            .get(credential_id)
            .cloned()
            .ok_or(StatusCode::NoCredentials)
    }

    fn update_credential(&self, credential: &Credential) -> Result<()> {
        let mut storage = self.credentials.lock().unwrap();
        storage.insert(credential.id.clone(), credential.clone());
        Ok(())
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        let storage = self.credentials.lock().unwrap();
        let mut rps: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in storage.values() {
            let entry = rps
                .entry(cred.rp_id.clone())
                .or_insert((cred.rp_name.clone(), 0));
            entry.1 += 1;
        }

        Ok(rps
            .into_iter()
            .map(|(id, (name, count))| (id, name, count))
            .collect())
    }

    fn credential_count(&self) -> Result<usize> {
        let storage = self.credentials.lock().unwrap();
        Ok(storage.len())
    }
}

/// Pure Rust authenticator
#[cfg(feature = "pure-rust")]
pub struct RustAuthenticator {
    inner: CtapAuthenticator<BridgeCallbacks>,
}

#[cfg(feature = "pure-rust")]
impl RustAuthenticator {
    /// Create a new authenticator with default configuration
    pub fn new(callbacks: BridgeCallbacks) -> Self {
        let config = CtapConfig::new();
        let inner = CtapAuthenticator::new(config, callbacks);
        Self { inner }
    }

    /// Create a new authenticator with custom configuration
    pub fn with_config(config: CtapConfig, callbacks: BridgeCallbacks) -> Self {
        let inner = CtapAuthenticator::new(config, callbacks);
        Self { inner }
    }

    /// Get a reference to the inner authenticator
    pub fn inner(&self) -> &CtapAuthenticator<BridgeCallbacks> {
        &self.inner
    }

    /// Get a mutable reference to the inner authenticator
    pub fn inner_mut(&mut self) -> &mut CtapAuthenticator<BridgeCallbacks> {
        &mut self.inner
    }
}
