//! Error types for hsinject-backend

use thiserror::Error;

/// Result type alias for hsinject operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for hsinject operations
#[derive(Debug, Error)]
pub enum Error {
    /// Process not found
    #[error("process not found: {0}")]
    ProcessNotFound(i32),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Ptrace operation failed
    #[error("ptrace error: {0}")]
    Ptrace(String),

    /// Memory operation failed
    #[error("memory error: {0}")]
    Memory(String),

    /// Library loading failed
    #[error("library load error: {0}")]
    LibraryLoad(String),

    /// Architecture not supported
    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
