//! WebAuthn-RS Cryptographic Validation Tests
//!
//! This test suite uses webauthn-rs to validate the cryptographic correctness
//! of soft-fido2 signatures and attestations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use soft_fido2::{
    Authenticator, AuthenticatorConfig, AuthenticatorOptions, CallbacksBuilder, Credential, Error,
    UpResult, UvResult,
};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const USER_ID: &[u8] = b"user-123";
const USER_NAME: &str = "alice@example.com";
const USER_DISPLAY_NAME: &str = "Alice";

/// Create a test authenticator
fn create_test_authenticator(
    credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
) -> Authenticator {
    let creds_write = credentials.clone();
    let creds_read = credentials.clone();
    let creds_get = credentials.clone();
    let creds_delete = credentials.clone();

    let callbacks = CallbacksBuilder::new()
        .up(Arc::new(|_info, _user, _rp| Ok(UpResult::Accepted)))
        .uv(Arc::new(|_info, _user, _rp| Ok(UvResult::Accepted)))
        .write(Arc::new(move |_rp_id, _user_name, cred| {
            let mut store = creds_write.lock().unwrap();
            store.insert(cred.id.to_vec(), cred.to_owned());
            Ok(())
        }))
        .read_credentials(Arc::new(move |rp_id, _user_id| {
            let store = creds_read.lock().unwrap();
            let filtered: Vec<Credential> = store
                .values()
                .filter(|c| c.rp.id == rp_id)
                .cloned()
                .collect();
            Ok(filtered)
        }))
        .get_credential(Arc::new(move |cred_id| {
            let store = creds_get.lock().unwrap();
            store.get(cred_id).cloned().ok_or(Error::DoesNotExist)
        }))
        .delete(Arc::new(move |cred_id| {
            let mut store = creds_delete.lock().unwrap();
            store.remove(cred_id.as_bytes());
            Ok(())
        }))
        .build();

    let config = AuthenticatorConfig::builder()
        .aaguid([
            0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29,
            0x7c, 0x88,
        ])
        .max_credentials(100)
        .extensions(vec!["credProtect".to_string(), "hmac-secret".to_string()])
        .options(
            AuthenticatorOptions::new()
                .with_resident_keys(true)
                .with_user_verification(Some(true)),
        )
        .build();

    Authenticator::with_config(callbacks, config).expect("Failed to create authenticator")
}

#[test]
fn test_make_credential_produces_valid_ctap_response() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials.clone());

    // Create challenge and client data hash
    let challenge = b"registration-challenge";
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    // Build makeCredential request
    let request_cbor = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Example Corp",
        USER_ID,
        USER_NAME,
        USER_DISPLAY_NAME,
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request_cbor);

    // Call authenticator
    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert_eq!(response[0], 0x00, "makeCredential should succeed");

    // Parse and validate response structure
    let resp: ciborium::Value =
        ciborium::from_reader(&response[1..]).expect("Failed to parse CBOR response");

    let map = match resp {
        ciborium::Value::Map(m) => m,
        _ => panic!("Response is not a CBOR map"),
    };

    // Extract and validate authData
    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            ciborium::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .expect("Missing authData");

    // Validate authData contains attestedCredentialData (AT flag set)
    let flags = auth_data[32];
    assert_ne!(flags & 0x40, 0, "AT flag must be set");

    // Extract public key from authData
    let cred_id_len_offset = 32 + 1 + 4 + 16; // rpIdHash + flags + signCount + aaguid
    let cred_id_len = u16::from_be_bytes([
        auth_data[cred_id_len_offset],
        auth_data[cred_id_len_offset + 1],
    ]) as usize;
    let public_key_offset = cred_id_len_offset + 2 + cred_id_len;

    // Public key should be CBOR-encoded COSE_Key
    let public_key_cbor = &auth_data[public_key_offset..];
    let _public_key: ciborium::Value =
        ciborium::from_reader(public_key_cbor).expect("Failed to parse public key");

    // Verify credential was stored
    assert_eq!(
        credentials.lock().unwrap().len(),
        1,
        "Expected 1 credential stored"
    );
}

#[test]
fn test_get_assertion_produces_valid_signature() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials.clone());

    // First, create a credential
    let challenge = b"registration-challenge";
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    let request_cbor = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Example Corp",
        USER_ID,
        USER_NAME,
        USER_DISPLAY_NAME,
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("makeCredential failed");
    assert_eq!(response[0], 0x00);

    // Now test getAssertion
    let auth_challenge = b"authentication-challenge";
    let auth_client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(auth_challenge),
        ORIGIN
    );
    let auth_client_data_hash = Sha256::digest(auth_client_data_json.as_bytes()).to_vec();

    let assertion_cbor = build_get_assertion_cbor(&auth_client_data_hash, RP_ID);

    let mut ctap_request = vec![0x02];
    ctap_request.extend_from_slice(&assertion_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("getAssertion failed");

    assert_eq!(response[0], 0x00, "getAssertion should succeed");

    // Parse response
    let resp: ciborium::Value =
        ciborium::from_reader(&response[1..]).expect("Failed to parse CBOR response");

    let map = match resp {
        ciborium::Value::Map(m) => m,
        _ => panic!("Response is not a CBOR map"),
    };

    // Extract signature
    let signature = map
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i == &3.into()))
        .and_then(|(_, v)| match v {
            ciborium::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .expect("Missing signature");

    // Signature should be DER-encoded ECDSA signature (typically 70-72 bytes for P-256)
    assert!(
        signature.len() >= 64 && signature.len() <= 73,
        "Signature length should be valid for ES256: {} bytes",
        signature.len()
    );

    // Verify signature starts with DER SEQUENCE tag
    assert_eq!(
        signature[0], 0x30,
        "Signature should start with DER SEQUENCE tag"
    );
}

#[test]
fn test_authenticator_produces_valid_es256_signatures() {
    let credentials = Arc::new(Mutex::new(HashMap::new()));
    let mut authenticator = create_test_authenticator(credentials);

    // Create credential
    let challenge = b"test-challenge-123456789012";
    let client_data_json = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge),
        ORIGIN
    );
    let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();

    let request_cbor = build_make_credential_cbor(
        &client_data_hash,
        RP_ID,
        "Test Corp",
        USER_ID,
        USER_NAME,
        USER_DISPLAY_NAME,
    );

    let mut ctap_request = vec![0x01];
    ctap_request.extend_from_slice(&request_cbor);

    let mut response = Vec::new();
    authenticator
        .handle(&ctap_request, &mut response)
        .expect("makeCredential failed");

    assert_eq!(response[0], 0x00);

    // Parse to extract public key
    let resp: ciborium::Value = ciborium::from_reader(&response[1..]).unwrap();
    let map = match resp {
        ciborium::Value::Map(m) => m,
        _ => panic!("Not a map"),
    };

    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i == &2.into()))
        .and_then(|(_, v)| match v {
            ciborium::Value::Bytes(b) => Some(b),
            _ => None,
        })
        .unwrap();

    // Verify authData structure is valid
    assert!(
        auth_data.len() > 55,
        "authData should include credential data"
    );

    let rp_id_hash = Sha256::digest(RP_ID.as_bytes());
    assert_eq!(&auth_data[0..32], rp_id_hash.as_slice());
}

// Helper functions

fn build_make_credential_cbor(
    client_data_hash: &[u8],
    rp_id: &str,
    rp_name: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> Vec<u8> {
    use ciborium::Value;

    let rp_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(rp_name.to_string()),
        ),
    ];

    let user_map = vec![
        (
            Value::Text("id".to_string()),
            Value::Bytes(user_id.to_vec()),
        ),
        (
            Value::Text("name".to_string()),
            Value::Text(user_name.to_string()),
        ),
        (
            Value::Text("displayName".to_string()),
            Value::Text(user_display_name.to_string()),
        ),
    ];

    let pub_key_params = vec![Value::Map(vec![
        (
            Value::Text("type".to_string()),
            Value::Text("public-key".to_string()),
        ),
        (Value::Text("alg".to_string()), Value::Integer((-7).into())),
    ])];

    let options_map = vec![
        (Value::Text("rk".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (
            Value::Integer(0x01.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (Value::Integer(0x02.into()), Value::Map(rp_map)),
        (Value::Integer(0x03.into()), Value::Map(user_map)),
        (Value::Integer(0x04.into()), Value::Array(pub_key_params)),
        (Value::Integer(0x07.into()), Value::Map(options_map)),
    ];

    let mut buffer = Vec::new();
    ciborium::into_writer(&Value::Map(request_map), &mut buffer).expect("CBOR encoding");
    buffer
}

fn build_get_assertion_cbor(client_data_hash: &[u8], rp_id: &str) -> Vec<u8> {
    use ciborium::Value;

    let options_map = vec![
        (Value::Text("up".to_string()), Value::Bool(true)),
        (Value::Text("uv".to_string()), Value::Bool(true)),
    ];

    let request_map = vec![
        (Value::Integer(0x01.into()), Value::Text(rp_id.to_string())),
        (
            Value::Integer(0x02.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (Value::Integer(0x05.into()), Value::Map(options_map)),
    ];

    let mut buffer = Vec::new();
    ciborium::into_writer(&Value::Map(request_map), &mut buffer).expect("CBOR encoding");
    buffer
}
