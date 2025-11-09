use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

/// Build from prebuilt artifacts downloaded from GitHub Releases
pub fn build() {
    let target = env::var("TARGET").unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();

    // Build URL for prebuilt artifacts
    let base_url = "https://github.com/pando85/rust-keylib/releases/download";
    let filename = format!("keylib-prebuilt-{}.tar.gz", target);
    let url = format!("{}/v{}/{}", base_url, version, filename);

    let out_dir = env::var("OUT_DIR").unwrap();
    let prebuilt_dir = PathBuf::from(&out_dir).join("prebuilt");

    // Download and extract if not already cached
    if !prebuilt_dir.exists() {
        download_and_extract(&url, &prebuilt_dir, target.as_str());
    }

    // Set up library paths
    setup_linking(&prebuilt_dir);

    // Generate FFI bindings
    generate_bindings(&prebuilt_dir);
}

/// Download prebuilt artifacts from GitHub Releases and verify checksum
fn download_and_extract(url: &str, prebuilt_dir: &PathBuf, target: &str) {
    fs::create_dir_all(prebuilt_dir).expect("Failed to create prebuilt directory");

    println!("Downloading prebuilt keylib artifacts from {}", url);
    println!(
        "cargo:warning=Downloading prebuilt artifacts for {}",
        target
    );

    // Download with timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .expect("Failed to create HTTP client");

    let response = client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .unwrap_or_else(|e| {
            panic!(
                "Failed to download prebuilt artifacts from {}.\n\
                     Error: {}\n\
                     If this release doesn't have prebuilt artifacts yet, \
                     try building from source by disabling the 'bundled' feature.",
                url, e
            )
        });

    let bytes = response.bytes().expect("Failed to read response bytes");

    // Verify checksum if available
    verify_checksum(&client, url, &bytes);

    // Extract tarball
    extract_tarball(&bytes, prebuilt_dir);
}

/// Verify SHA-256 checksum of downloaded artifact
fn verify_checksum(client: &reqwest::blocking::Client, url: &str, bytes: &[u8]) {
    let checksum_url = format!("{}.sha256", url);

    if let Ok(checksum_response) = client.get(&checksum_url).send() {
        if let Ok(expected_checksum) = checksum_response.text() {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let actual_checksum = format!("{:x}", hasher.finalize());
            let expected = expected_checksum.split_whitespace().next().unwrap_or("");

            if actual_checksum != expected {
                panic!(
                    "Checksum mismatch! Expected: {}, Got: {}",
                    expected, actual_checksum
                );
            }
            println!("cargo:warning=Checksum verified successfully");
        }
    }
}

/// Extract tarball to destination directory
fn extract_tarball(bytes: &[u8], dest: &PathBuf) {
    let tar_gz = GzDecoder::new(bytes);
    let mut archive = Archive::new(tar_gz);
    archive
        .unpack(dest)
        .expect("Failed to extract prebuilt artifacts");

    println!(
        "cargo:warning=Extracted prebuilt artifacts to {}",
        dest.display()
    );
}

/// Configure linker to use prebuilt libraries
fn setup_linking(prebuilt_dir: &Path) {
    let lib_dir = prebuilt_dir.join("lib");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=keylib");
    println!("cargo:rustc-link-lib=static=uhid");
}

/// Generate Rust FFI bindings from prebuilt C headers
fn generate_bindings(prebuilt_dir: &Path) {
    let include_dir = prebuilt_dir.join("include");
    let keylib_header = include_dir.join("keylib.h");
    let uhid_header = include_dir.join("uhid.h");

    // Validate headers exist
    if !keylib_header.exists() || !uhid_header.exists() {
        panic!(
            "Prebuilt artifacts missing required headers. \
                 Expected headers in {}",
            include_dir.display()
        );
    }

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header(keylib_header.to_str().unwrap())
        .header(uhid_header.to_str().unwrap())
        .clang_arg(format!("-I{}", include_dir.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to OUT_DIR
    let out_path = std::path::PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
