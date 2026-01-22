//! Test library for hsinject integration tests

use std::fs;
use std::ffi::CStr;

/// Marker file to verify injection
const MARKER_FILE: &str = "/tmp/hsinject_test_marker";

/// Constructor - called when library is loaded via dlopen
#[ctor::ctor]
fn constructor() {
    let _ = fs::write(MARKER_FILE, "constructor_called");
}

/// Entry point function for testing
#[no_mangle]
pub extern "C" fn test_entry(arg: *const libc::c_char) -> libc::c_int {
    let arg_str = if arg.is_null() {
        "null".to_string()
    } else {
        unsafe { CStr::from_ptr(arg).to_string_lossy().into_owned() }
    };

    let content = format!("entry_called:{}", arg_str);
    let _ = fs::write(MARKER_FILE, content);

    42 // return value
}
