//! Build script for hsinject
//!
//! Compiles the C bootstrapper shellcode using Make and embeds it.
//! Supports x86_64 and aarch64 architectures.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    // Bootstrapper source directory (in package directory)
    let bootstrapper_dir = manifest_dir.join("bootstrapper");

    // Track changes
    println!("cargo:rerun-if-changed={}", bootstrapper_dir.display());

    // Map Rust target arch to bootstrapper ARCH
    let (arch, bin_name) = match target_arch.as_str() {
        "x86_64" => ("x86_64", "bootstrapper-x86_64.bin"),
        "aarch64" => ("aarch64", "bootstrapper-aarch64.bin"),
        arch => panic!("Unsupported architecture: {}. Supported: x86_64, aarch64", arch),
    };

    // Build bootstrapper using make
    let status = Command::new("make")
        .arg("-C")
        .arg(&bootstrapper_dir)
        .arg(format!("OUT_DIR={}", out_dir.display()))
        .arg(format!("ARCH={}", arch))
        .status()
        .expect("Failed to run make. Ensure make and gcc are installed.");

    if !status.success() {
        panic!("Failed to build bootstrapper for {}", arch);
    }

    // Verify output
    let bin_file = out_dir.join(bin_name);
    if !bin_file.exists() {
        panic!("Bootstrapper binary not found at {:?}", bin_file);
    }

    let metadata = std::fs::metadata(&bin_file).expect("Failed to stat bootstrapper binary");
    println!(
        "cargo:warning=Bootstrapper shellcode size ({arch}): {} bytes",
        metadata.len()
    );
}
