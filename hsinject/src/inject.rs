//! Library injection implementation
//!
//! This module provides the main injection functions that inject
//! a shared library into a running process using ptrace and call functions.
//!
//! Uses Frida-style two-stage injection:
//! - Stage 1: Bootstrap code resolves libc symbols in hijacked thread
//! - Stage 2: New thread does dlopen + dlsym + call (clean context, single reference)

use std::path::Path;

use nix::unistd::Pid;

use crate::bootstrap;
use crate::call::remote_mmap;
use crate::error::{Error, Result};
use crate::ptrace::TracedProcess;

/// Result of a successful injection
#[derive(Debug)]
pub struct InjectionResult {
    /// The target process ID
    pub pid: i32,
    /// The handle returned by dlopen (can be used for dlsym)
    pub handle: u64,
}

/// Result of injection with function call
#[derive(Debug)]
pub struct InjectionCallResult {
    /// The target process ID
    pub pid: i32,
    /// The handle returned by dlopen
    pub handle: u64,
}

/// Canonicalize library path and convert to String
fn canonicalize_path(library_path: &Path) -> Result<String> {
    library_path
        .canonicalize()?
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid path encoding",
            ))
        })
        .map(String::from)
}

/// Inject a shared library into a running process
///
/// This function performs the following steps:
/// 1. Attaches to the process with ptrace
/// 2. Allocates RWX memory in the target using mmap syscall
/// 3. Executes bootstrapper which:
///    - Resolves libc symbols (dlopen, pthread_create, etc.)
///    - Creates a new thread
///    - Thread calls dlopen to load the library
/// 4. Restores the process state and detaches
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
///
/// # Returns
/// `InjectionResult` containing the dlopen handle on success
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_library;
///
/// let result = inject_library(1234, Path::new("/path/to/library.so")).unwrap();
/// println!("Injected! handle = 0x{:x}", result.handle);
/// ```
pub fn inject_library(_pid: i32, _library_path: &Path) -> Result<InjectionResult> {
    // Use inject_and_call with a dummy function that just returns
    // For now, require at least one exported function
    // TODO: Support pure dlopen without function call
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "inject_library without function call is not supported; use inject_and_call instead",
    )))
}

/// Internal helper for injection with optional string argument
fn inject_impl(
    pid: i32,
    library_path: &Path,
    function_name: &str,
    argument: Option<&str>,
) -> Result<InjectionCallResult> {
    let lib_path_str = canonicalize_path(library_path)?;

    let proc = TracedProcess::attach(Pid::from_raw(pid))?;
    let mem_size = bootstrap::required_memory_size();
    let remote_mem = remote_mmap(&proc, mem_size)?;

    eprintln!("[debug] allocated {} bytes @ 0x{:x}", mem_size, remote_mem);

    let result = bootstrap::inject_library(
        &proc,
        remote_mem,
        &lib_path_str,
        function_name,
        argument,
    )?;

    proc.detach()?;

    Ok(InjectionCallResult {
        pid,
        handle: result.handle,
    })
}

/// Inject a shared library and call a function with arguments
///
/// This extends `inject_library` by also calling a specified function
/// from the injected library. Uses Frida-style injection where:
/// - dlopen happens in a new thread (single reference count)
/// - Library can properly unload via dlclose
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
/// * `function_name` - Name of the function to call after injection
/// * `args` - Arguments to pass to the function (currently unused)
///
/// # Returns
/// `InjectionCallResult` containing the handle
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_and_call;
///
/// let result = inject_and_call(
///     1234,
///     Path::new("/path/to/library.so"),
///     "entry",
///     &[],
/// ).unwrap();
/// println!("Function started in new thread, handle: 0x{:x}", result.handle);
/// ```
pub fn inject_and_call(
    pid: i32,
    library_path: &Path,
    function_name: &str,
    _args: &[u64],
) -> Result<InjectionCallResult> {
    inject_impl(pid, library_path, function_name, None)
}

/// Inject a shared library and call a function with a string argument
///
/// Similar to `inject_and_call`, but passes a string as the first argument
/// to the function. The string is written to the target process memory.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
/// * `function_name` - Name of the function to call (should accept `const char*`)
/// * `data` - String data to pass to the function
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_and_call_with_string;
///
/// let result = inject_and_call_with_string(
///     1234,
///     Path::new("/path/to/library.so"),
///     "init",
///     "window:0x5a00023",
/// ).unwrap();
/// ```
pub fn inject_and_call_with_string(
    pid: i32,
    library_path: &Path,
    function_name: &str,
    data: &str,
) -> Result<InjectionCallResult> {
    inject_impl(pid, library_path, function_name, Some(data))
}

/// Call a function in an already-loaded library
///
/// This uses CALL mode to find a library by pattern in the target's link_map
/// and call a function. Useful for:
/// - Calling unload functions in previously injected libraries
/// - Calling functions in libraries the target already has loaded
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_pattern` - Substring to match against library paths in link_map
/// * `function_name` - Name of the function to call
/// * `data` - Optional string data to pass to the function
///
/// # Example
/// ```no_run
/// use hsinject::call_in_loaded_library;
///
/// // Call unload in a previously injected library
/// call_in_loaded_library(1234, "libpayload.so", "unload", None).unwrap();
/// ```
pub fn call_in_loaded_library(
    pid: i32,
    library_pattern: &str,
    function_name: &str,
    data: Option<&str>,
) -> Result<()> {
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;
    let mem_size = bootstrap::required_memory_size();
    let remote_mem = remote_mmap(&proc, mem_size)?;

    eprintln!("[debug] allocated {} bytes @ 0x{:x} (CALL mode)", mem_size, remote_mem);

    bootstrap::call_in_library(
        &proc,
        remote_mem,
        library_pattern,
        function_name,
        data,
    )?;

    proc.detach()?;

    Ok(())
}
