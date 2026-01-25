//! Build script for hsinject
//!
//! Compiles the C bootstrapper shellcode using Make and embeds it.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));

    // Bootstrapper source directory (in workspace root)
    let workspace_dir = manifest_dir.parent().expect("No parent directory");
    let bootstrapper_dir = workspace_dir.join("bootstrapper");

    // Track changes
    println!("cargo:rerun-if-changed={}", bootstrapper_dir.display());

    // Build bootstrapper using make
    let status = Command::new("make")
        .arg("-C")
        .arg(&bootstrapper_dir)
        .arg(format!("OUT_DIR={}", out_dir.display()))
        .arg("ARCH=x86_64")
        .status()
        .expect("Failed to run make. Ensure make and gcc are installed.");

    if !status.success() {
        panic!("Failed to build bootstrapper");
    }

    // Verify output
    let bin_file = out_dir.join("bootstrapper-x86_64.bin");
    if !bin_file.exists() {
        panic!("Bootstrapper binary not found at {:?}", bin_file);
    }

    let metadata = std::fs::metadata(&bin_file).expect("Failed to stat bootstrapper binary");
    println!(
        "cargo:warning=Bootstrapper shellcode size: {} bytes",
        metadata.len()
    );
}
