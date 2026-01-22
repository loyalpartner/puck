//! Architecture-specific code
//!
//! Uses cfg conditional compilation (Frida style) to select
//! the appropriate implementation at compile time.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

// Ensure we have an implementation for the current architecture
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture");
