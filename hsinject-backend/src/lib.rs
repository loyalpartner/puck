//! hsinject-backend - Platform-specific injection implementation

pub mod error;
pub mod arch;

#[cfg(target_os = "linux")]
pub mod linux;
