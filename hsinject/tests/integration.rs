//! Integration tests for hsinject
//!
//! These tests require:
//! 1. Root privileges (for ptrace)
//! 2. Built test library (cargo build -p test_lib)

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use hsinject::{inject, InjectOptions, Payload};

const MARKER_FILE: &str = "/tmp/hsinject_test_marker";

fn cleanup_marker() {
    let _ = fs::remove_file(MARKER_FILE);
}

fn read_marker() -> Option<String> {
    fs::read_to_string(MARKER_FILE).ok()
}

fn spawn_target() -> std::process::Child {
    Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn target process")
}

fn get_test_lib_path() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("target/debug/libtest_lib.so")
}

#[test]
#[ignore] // requires root
fn test_inject_library_constructor() {
    cleanup_marker();

    let mut child = spawn_target();
    let pid = child.id() as i32;

    let lib_path = get_test_lib_path();
    if !lib_path.exists() {
        eprintln!("Test library not found at {:?}, skipping", lib_path);
        child.kill().ok();
        return;
    }

    let result = inject(pid, Payload::Library(lib_path), InjectOptions::default());

    // Give constructor time to run
    thread::sleep(Duration::from_millis(100));

    child.kill().ok();

    assert!(result.is_ok(), "injection failed: {:?}", result.err());
    let result = result.unwrap();
    assert_ne!(result.handle, 0, "dlopen returned null handle");

    let marker = read_marker();
    assert_eq!(marker, Some("constructor_called".to_string()));

    cleanup_marker();
}

#[test]
#[ignore] // requires root
fn test_inject_library_with_entry_point() {
    cleanup_marker();

    let mut child = spawn_target();
    let pid = child.id() as i32;

    let lib_path = get_test_lib_path();
    if !lib_path.exists() {
        eprintln!("Test library not found at {:?}, skipping", lib_path);
        child.kill().ok();
        return;
    }

    let result = inject(
        pid,
        Payload::Library(lib_path),
        InjectOptions {
            entry_point: Some("test_entry".to_string()),
            argument: Some("hello".to_string()),
        },
    );

    thread::sleep(Duration::from_millis(100));

    child.kill().ok();

    assert!(result.is_ok(), "injection failed: {:?}", result.err());
    let result = result.unwrap();
    assert_ne!(result.handle, 0);
    assert_eq!(result.retval, 42);

    let marker = read_marker();
    assert_eq!(marker, Some("entry_called:hello".to_string()));

    cleanup_marker();
}

#[test]
#[ignore] // requires root
fn test_inject_nonexistent_process() {
    let result = inject(
        999999,
        Payload::Library("/tmp/test.so".into()),
        InjectOptions::default(),
    );

    assert!(result.is_err());
}
