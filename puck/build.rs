//! Build script for hsinject
//!
//! Compiles the C bootstrapper shellcode using Make and embeds it.
//! Supports x86_64 and aarch64 architectures.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(&bootstrapper_dir)
        .arg(format!("OUT_DIR={}", out_dir.display()))
        .arg(format!("ARCH={}", arch));

    for (var, value) in cross_tool_overrides(&target_arch, arch) {
        cmd.arg(format!("{var}={value}"));
    }

    let status = cmd
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

/// The Makefile only bakes in a real cross-toolchain default for the
/// aarch64/arm branches (`aarch64-linux-gnu-gcc` etc, used by `make
/// build-aarch64` from an x86_64 host). The x86_64/x86 branches hardcode
/// plain `gcc`/`ld`/`objcopy`, which is only correct when building natively
/// on an x86 host. When cross-compiling to x86_64 from a non-x86 host (e.g.
/// an aarch64 dev machine), resolve working cross tools here and pass them
/// through `make CC=... LD=... OBJCOPY=...` (command-line make vars override
/// the Makefile's `:=` defaults).
fn cross_tool_overrides(target_arch: &str, bootstrap_arch: &str) -> Vec<(&'static str, String)> {
    let host = env::var("HOST").unwrap_or_default();
    if host.starts_with(target_arch) {
        return vec![]; // native build, Makefile's own default is correct
    }
    if bootstrap_arch != "x86_64" {
        return vec![]; // aarch64/arm branches already pick a cross-compiler
    }

    let cc = resolve_cc();
    // A working CC implies a matching binutils cross package is installed
    // alongside it (Debian/Ubuntu ship them together), so derive LD/OBJCOPY
    // from the same `<prefix>-` naming convention rather than probing twice.
    let prefix = cc.strip_suffix("-gcc").map(str::to_string);
    let ld = prefix
        .as_deref()
        .map(|p| format!("{p}-ld"))
        .unwrap_or_else(|| "ld".to_string());
    let objcopy = prefix
        .as_deref()
        .map(|p| format!("{p}-objcopy"))
        .unwrap_or_else(|| "objcopy".to_string());

    vec![("CC", cc), ("LD", ld), ("OBJCOPY", objcopy)]
}

/// Resolve a working x86_64 C compiler when cross-compiling. Priority:
/// 1. The same override convention as the `cc` crate (cc-rs), so this
///    composes with existing cross setups — including this project's own
///    `cargo zigbuild` targets, which set `CC_<target>` to a `zig cc
///    -target ...` wrapper.
/// 2. Auto-probe the common Debian/Ubuntu cross package name.
/// 3. Fail loud with an actionable message — silently falling back to plain
///    `gcc` here would resurface the exact confusing "unrecognized
///    command-line option '-m64'" failure this exists to fix.
fn resolve_cc() -> String {
    let target = env::var("TARGET").unwrap_or_default();
    let target_env = target.replace('-', "_");
    for key in [
        format!("CC_{target_env}"),
        format!("CC_{target}"),
        "TARGET_CC".to_string(),
        "CC".to_string(),
    ] {
        if let Ok(v) = env::var(&key) {
            if !v.is_empty() {
                return v;
            }
        }
    }

    const CANDIDATE: &str = "x86_64-linux-gnu-gcc";
    let found = Command::new(CANDIDATE)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if found {
        return CANDIDATE.to_string();
    }

    panic!(
        "cross-compiling to x86_64 but no working C compiler found. \
         Install one (e.g. `apt install gcc-x86-64-linux-gnu` on Debian/Ubuntu) \
         or set CC_{target_env} to an x86_64 cross-compiler."
    );
}
