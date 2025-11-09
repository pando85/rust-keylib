use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Build keylib from source using Zig compiler
pub fn build() {
    let keylib_dir = get_keylib_directory();

    // Ensure Zig is installed
    check_zig_available();

    // Build keylib with Zig
    build_with_zig(&keylib_dir);

    // Set up library paths
    setup_linking(&keylib_dir);

    // Generate FFI bindings
    generate_bindings(&keylib_dir);

    // Watch for changes
    println!("cargo:rerun-if-changed=keylib/");
}

/// Get the path to the keylib source directory
fn get_keylib_directory() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // keylib submodule is always at {CARGO_MANIFEST_DIR}/keylib
    PathBuf::from(manifest_dir).join("keylib")
}

/// Check if Zig compiler is available and provide helpful error message
fn check_zig_available() {
    if Command::new("zig").arg("version").output().is_err() {
        eprintln!("\n========================================");
        eprintln!("ERROR: Zig compiler not found!");
        eprintln!("========================================\n");
        eprintln!("You have two options:\n");
        eprintln!("1. Install Zig compiler:");
        eprintln!("   - Visit: https://ziglang.org/download/");
        eprintln!("   - Or use your package manager\n");
        eprintln!("2. Use prebuilt binaries (easier):");
        eprintln!("   Add to your Cargo.toml:");
        eprintln!("   keylib = {{ version = \"*\", features = [\"bundled\"] }}\n");
        eprintln!("========================================\n");
        panic!("Zig compiler required for building from source");
    }
}

/// Build keylib using Zig build system
fn build_with_zig(keylib_dir: &PathBuf) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let prefix_dir = PathBuf::from(&out_dir).join("zig-install");
    let cache_dir = PathBuf::from(&out_dir).join("zig-cache");

    println!("cargo:warning=Building keylib from source");
    println!("cargo:warning=Keylib dir: {}", keylib_dir.display());
    println!("cargo:warning=Prefix dir: {}", prefix_dir.display());
    println!("cargo:warning=Cache dir: {}", cache_dir.display());

    // Ensure clean build directories
    let _ = std::fs::remove_dir_all(&prefix_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
    std::fs::create_dir_all(&prefix_dir).expect("Failed to create prefix dir");
    std::fs::create_dir_all(&cache_dir).expect("Failed to create cache dir");

    let output = Command::new("zig")
        .args([
            "build",
            "install",
            "--prefix",
            prefix_dir.to_str().unwrap(),
            "--cache-dir",
            cache_dir.to_str().unwrap(),
        ])
        .current_dir(keylib_dir)
        .output()
        .expect("Failed to execute Zig build command");

    if !output.status.success() {
        println!(
            "cargo:warning=Zig stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "cargo:warning=Zig stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        panic!(
            "Zig build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Configure linker to use libraries built from source
fn setup_linking(_keylib_dir: &Path) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let lib_dir = PathBuf::from(out_dir).join("zig-install").join("lib");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=keylib");
    println!("cargo:rustc-link-lib=static=uhid");
}

/// Generate Rust FFI bindings from source C headers
fn generate_bindings(keylib_dir: &Path) {
    let keylib_include = keylib_dir.join("bindings/c/include");
    let uhid_include = keylib_dir.join("bindings/linux/include");

    let bindings = bindgen::Builder::default()
        .header(keylib_include.join("keylib.h").to_str().unwrap())
        .header(uhid_include.join("uhid.h").to_str().unwrap())
        .clang_arg(format!("-I{}", keylib_include.display()))
        .clang_arg(format!("-I{}", uhid_include.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
