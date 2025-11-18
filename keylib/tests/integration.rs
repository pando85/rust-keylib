//! Integration tests for keylib
//!
//! Tests work with both pure-rust (default) and zig-ffi implementations

#[cfg(feature = "pure-rust")]
mod pure_rust_tests {
    use keylib::rust_impl::authenticator::{BridgeCallbacks, RustAuthenticator};
    use keylib_ctap::authenticator::AuthenticatorConfig;
    use keylib_ctap::callbacks::UpResult;

    #[test]
    fn test_authenticator_creation() {
        let callbacks = BridgeCallbacks::new();
        let config = AuthenticatorConfig::new();
        let _auth = RustAuthenticator::with_config(config, callbacks);

        // Authenticator created successfully
    }

    #[test]
    fn test_callbacks_with_up() {
        let callbacks = BridgeCallbacks::new()
            .with_up_callback(|_, _, _| Ok(UpResult::Accepted));

        let config = AuthenticatorConfig::new();
        let _auth = RustAuthenticator::with_config(config, callbacks);
        // Authenticator created successfully with callbacks
    }

    #[test]
    fn test_credential_storage() {
        use keylib_ctap::types::Credential;
        use keylib_ctap::types::CoseAlgorithm;
        use keylib_ctap::callbacks::CredentialStorageCallbacks;

        let callbacks = BridgeCallbacks::new();

        // Create a test credential
        let cred = Credential {
            id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_string(),
            rp_name: Some("Example".to_string()),
            user_id: vec![5, 6, 7, 8],
            user_name: Some("user@example.com".to_string()),
            user_display_name: Some("Test User".to_string()),
            sign_count: 0,
            algorithm: CoseAlgorithm::ES256 as i32,
            private_key: vec![0u8; 32],
            created: 0,
            discoverable: true,
            cred_protect: 1,
        };

        // Test storage callbacks
        assert!(callbacks.write_credential(&cred).is_ok());
        assert!(callbacks.credential_exists(&cred.id).unwrap());
        assert!(callbacks.get_credential(&cred.id).is_ok());
    }
}

#[cfg(feature = "zig-ffi")]
mod zig_ffi_tests {
    use keylib::client;

    #[test]
    fn test_transport_enumeration() {
        // May fail if no devices available
        let _ = client::TransportList::enumerate();
    }

    #[test]
    fn test_authenticator_get_info() {
        let list = match client::TransportList::enumerate() {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Failed to enumerate transports: {:?}", e);
                return;
            }
        };

        if list.is_empty() {
            eprintln!("No devices available, skipping test");
            return;
        }

        let mut transport = match list.get(0) {
            Some(t) => t,
            None => {
                eprintln!("Failed to get transport at index 0");
                return;
            }
        };

        if let Err(e) = transport.open() {
            eprintln!("Failed to open transport: {:?}, skipping test", e);
            return;
        }

        let mut cmd = match client::Client::authenticator_get_info(&mut transport) {
            Ok(cmd) => cmd,
            Err(e) => {
                eprintln!("Failed to get authenticator info: {:?}", e);
                return;
            }
        };

        let result = match cmd.get_result(5000) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to get command result: {:?}", e);
                return;
            }
        };

        assert!(result.is_fulfilled());
        if let Some(data) = result.get_data() {
            assert!(!data.is_empty());
        }
    }
}
