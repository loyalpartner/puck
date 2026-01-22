//! hsinject - Linux process injection library

pub use hsinject_backend::error::{Error, Result};

use std::path::PathBuf;

/// Injection payload
pub enum Payload {
    /// Shared library (.so) path
    Library(PathBuf),
    /// Raw shellcode bytes
    Shellcode(Vec<u8>),
}

/// Injection options
#[derive(Default)]
pub struct InjectOptions {
    /// Entry point function name (for library injection)
    pub entry_point: Option<String>,
    /// Argument to pass to entry point
    pub argument: Option<String>,
}

/// Injection result
pub struct InjectResult {
    /// Target process ID
    pub pid: i32,
    /// dlopen handle (for library injection)
    pub handle: u64,
    /// Entry point return value
    pub retval: u64,
}

/// Inject payload into a running process
pub fn inject(_pid: i32, _payload: Payload, _options: InjectOptions) -> Result<InjectResult> {
    todo!()
}
