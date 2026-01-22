//! hsinject - Linux process injection library
//!
//! # Example
//!
//! ```no_run
//! use hsinject::{inject, Payload, InjectOptions};
//!
//! let result = inject(
//!     1234,
//!     Payload::Library("/path/to/lib.so".into()),
//!     InjectOptions {
//!         entry_point: Some("my_init".into()),
//!         argument: Some("config=debug".into()),
//!     },
//! ).unwrap();
//!
//! println!("Injected! handle=0x{:x}", result.handle);
//! ```

pub use hsinject_backend::error::{Error, Result};

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use hsinject_backend::linux::inject::{inject_library, inject_shellcode};

/// Injection payload
pub enum Payload {
    /// Shared library (.so) path
    Library(PathBuf),
    /// Raw shellcode bytes
    Shellcode(Vec<u8>),
}

/// Injection options
#[derive(Default, Clone)]
pub struct InjectOptions {
    /// Entry point function name (for library injection)
    ///
    /// If specified, after loading the library, this function will be called
    /// with the `argument` as its parameter.
    pub entry_point: Option<String>,

    /// Argument to pass to entry point function
    ///
    /// Passed as a C string pointer to the entry point function.
    pub argument: Option<String>,
}

/// Injection result
#[derive(Debug)]
pub struct InjectResult {
    /// Target process ID
    pub pid: i32,
    /// dlopen handle (for library injection, 0 for shellcode)
    pub handle: u64,
    /// Entry point return value (or shellcode return value)
    pub retval: u64,
}

/// Inject payload into a running process
///
/// # Arguments
///
/// * `pid` - Target process ID
/// * `payload` - What to inject (library or shellcode)
/// * `options` - Injection options (entry point, argument)
///
/// # Returns
///
/// `InjectResult` containing the dlopen handle and entry point return value
///
/// # Errors
///
/// Returns an error if:
/// - Cannot attach to the process (permission denied, process not found)
/// - Cannot allocate memory in the target process
/// - dlopen fails to load the library
/// - dlsym fails to find the entry point
///
/// # Example
///
/// ```no_run
/// use hsinject::{inject, Payload, InjectOptions};
///
/// // Simple library injection
/// let result = inject(
///     1234,
///     Payload::Library("/tmp/hook.so".into()),
///     InjectOptions::default(),
/// )?;
/// # Ok::<(), hsinject::Error>(())
/// ```
#[cfg(target_os = "linux")]
pub fn inject(pid: i32, payload: Payload, options: InjectOptions) -> Result<InjectResult> {
    match payload {
        Payload::Library(path) => {
            let result = inject_library(
                pid,
                &path,
                options.entry_point.as_deref(),
                options.argument.as_deref(),
            )?;
            Ok(InjectResult {
                pid: result.pid,
                handle: result.handle,
                retval: result.retval,
            })
        }
        Payload::Shellcode(code) => {
            let result = inject_shellcode(pid, &code)?;
            Ok(InjectResult {
                pid: result.pid,
                handle: result.handle,
                retval: result.retval,
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn inject(_pid: i32, _payload: Payload, _options: InjectOptions) -> Result<InjectResult> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "injection is only supported on Linux",
    )))
}
