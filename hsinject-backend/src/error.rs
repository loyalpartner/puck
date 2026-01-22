//! Error types for hsinject

use std::path::PathBuf;
use nix::errno::Errno;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // === Ptrace ===
    #[error("failed to attach to process {pid}: {source}")]
    AttachFailed { pid: i32, source: Errno },

    #[error("failed to detach from process {pid}: {source}")]
    DetachFailed { pid: i32, source: Errno },

    #[error("failed to get/set registers: {0}")]
    RegAccessFailed(Errno),

    #[error("failed to read memory at 0x{addr:x}: {source}")]
    MemReadFailed { addr: u64, source: Errno },

    #[error("failed to write memory at 0x{addr:x}: {source}")]
    MemWriteFailed { addr: u64, source: Errno },

    // === Process state ===
    #[error("process {pid} terminated with signal {signal}")]
    ProcessTerminated { pid: i32, signal: i32 },

    #[error("unexpected signal {signal}, expected SIGTRAP")]
    UnexpectedSignal { signal: i32 },

    #[error("process {pid} not found")]
    ProcessNotFound { pid: i32 },

    #[error("timeout waiting for process {pid}")]
    Timeout { pid: i32 },

    // === Symbol resolution ===
    #[error("libc not found in process {pid}")]
    LibcNotFound { pid: i32 },

    #[error("symbol '{symbol}' not found in {library}")]
    SymbolNotFound { symbol: String, library: String },

    #[error("failed to parse /proc/{pid}/maps: {reason}")]
    MapsParseError { pid: i32, reason: String },

    // === Injection ===
    #[error("remote mmap failed, returned 0x{addr:x}")]
    MmapFailed { addr: u64 },

    #[error("dlopen failed for '{path}'")]
    DlopenFailed { path: PathBuf },

    #[error("dlsym failed for '{symbol}'")]
    DlsymFailed { symbol: String },

    // === Input validation ===
    #[error("invalid library path: {0}")]
    InvalidPath(PathBuf),

    #[error("path too long: max {max} bytes, got {actual}")]
    PathTooLong { max: usize, actual: usize },

    #[error("entry point name too long: max {max} bytes")]
    EntryPointTooLong { max: usize },

    #[error("argument too long: max {max} bytes")]
    ArgumentTooLong { max: usize },

    // === Permission ===
    #[error("permission denied: cannot ptrace process {pid} (try running as root)")]
    PermissionDenied { pid: i32 },

    // === IO ===
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convert ptrace attach error to appropriate Error variant
    pub fn from_attach(pid: i32, errno: Errno) -> Self {
        match errno {
            Errno::EPERM => Error::PermissionDenied { pid },
            Errno::ESRCH => Error::ProcessNotFound { pid },
            _ => Error::AttachFailed { pid, source: errno },
        }
    }
}
