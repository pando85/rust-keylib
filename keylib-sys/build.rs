use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let keylib_dir = PathBuf::from(manifest_dir.clone())
        .parent()
        .unwrap()
        .join("keylib-sys/keylib");
    let output = std::process::Command::new("zig")
        .args(["build", "install"])
        .current_dir(&keylib_dir)
        .output()
        .expect("Failed to build Zig libraries");

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

    println!("cargo:rerun-if-changed=keylib/");
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

    println!("cargo:rustc-link-lib=static=keylib");
    println!("cargo:rustc-link-lib=static=uhid");

    let lib_dir = keylib_dir.join("zig-out").join("lib");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
}
