//! Error types

use std::path::PathBuf;
use nix::errno::Errno;
use thiserror::Error;

use crate::bootstrap::BootstrapStatus;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to attach to process {pid}: {source}")]
    AttachFailed { pid: i32, source: Errno },

    #[error("failed to detach from process {pid}: {source}")]
    DetachFailed { pid: i32, source: Errno },

    #[error("ptrace error: {0}")]
    Ptrace(Errno),

    #[error("process {pid} not found")]
    ProcessNotFound { pid: i32 },

    #[error("libc not found in process {pid}")]
    LibcNotFound { pid: i32 },

    #[error("symbol '{symbol}' not found in {path}")]
    SymbolNotFound { symbol: String, path: String },

    #[error("unexpected wait status: {0}")]
    UnexpectedWaitStatus(i32),

    #[error("process crashed with signal {signal}")]
    ProcessCrashed { signal: i32 },

    #[error("mmap failed in remote process")]
    MmapFailed,

    #[error("no suitable executable memory region found")]
    NoExecutableMemory,

    #[error("dlopen failed for {path}")]
    DlopenFailed { path: PathBuf },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("elf parse error: {0}")]
    ElfParse(String),

    #[error("bootstrap failed ({status:?}): {message}")]
    BootstrapFailed {
        status: BootstrapStatus,
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
