//! Libc symbol resolution using local libc offsets
//!
//! This module implements Frida-style symbol resolution:
//! 1. Find local libc path and base address
//! 2. Use dlsym to get function addresses
//! 3. Calculate offsets from base
//! 4. Apply offsets to remote libc base

use std::sync::OnceLock;

use crate::elf::parse_maps;
use crate::error::{Error, Result};

/// Cached libc function offsets (resolved once from local libc)
#[derive(Debug, Clone)]
pub struct LibcOffsets {
    pub mmap_offset: u64,
    pub libc_path: String,
}

/// Global cache for libc offsets (Ok variant) or None if not yet resolved
static LIBC_OFFSETS: OnceLock<Option<LibcOffsets>> = OnceLock::new();

impl LibcOffsets {
    /// Resolve offsets from local libc (only needs to be done once)
    pub fn resolve() -> Result<Self> {
        // Find local libc path and base address
        let (local_base, libc_path) = find_local_libc()?;

        // Use dlsym to get mmap address
        let mmap_addr = unsafe {
            libc::dlsym(libc::RTLD_DEFAULT, c"mmap".as_ptr())
        };

        if mmap_addr.is_null() {
            return Err(Error::SymbolNotFound {
                symbol: "mmap".to_string(),
                path: libc_path,
            });
        }

        // Calculate offset from base
        Ok(Self {
            mmap_offset: mmap_addr as u64 - local_base,
            libc_path,
        })
    }

    /// Get cached offsets or resolve them
    pub fn get() -> Result<&'static Self> {
        let cached = LIBC_OFFSETS.get_or_init(|| Self::resolve().ok());
        cached.as_ref().ok_or_else(|| Error::LibcNotFound {
            pid: std::process::id() as i32,
        })
    }
}

/// Find local libc path and base address from /proc/self/maps
fn find_local_libc() -> Result<(u64, String)> {
    let maps = parse_maps(std::process::id() as i32)?;

    for mapping in maps {
        if let Some(ref path) = mapping.path {
            if is_libc_path(path) && mapping.perms.contains('x') {
                return Ok((mapping.start, path.clone()));
            }
        }
    }

    Err(Error::LibcNotFound { pid: std::process::id() as i32 })
}

/// Find remote libc base address in target process
pub fn find_remote_libc_base(pid: i32, expected_path: &str) -> Result<u64> {
    let maps = parse_maps(pid)?;

    // First try exact path match
    for mapping in &maps {
        if let Some(ref path) = mapping.path {
            if path == expected_path && mapping.perms.contains('x') {
                return Ok(mapping.start);
            }
        }
    }

    // Fallback: match any libc (for different distro paths)
    for mapping in &maps {
        if let Some(ref path) = mapping.path {
            if is_libc_path(path) && mapping.perms.contains('x') {
                return Ok(mapping.start);
            }
        }
    }

    Err(Error::LibcNotFound { pid })
}

/// Check if a path looks like libc
fn is_libc_path(path: &str) -> bool {
    // Common libc patterns:
    // - /lib/x86_64-linux-gnu/libc.so.6
    // - /lib64/libc.so.6
    // - /usr/lib/libc.so.6
    // - /lib/aarch64-linux-gnu/libc.so.6
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    filename.starts_with("libc.so") || filename.starts_with("libc-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_local_libc() {
        let offsets = LibcOffsets::resolve().expect("should resolve libc offsets");
        assert!(offsets.mmap_offset > 0, "mmap offset should be non-zero");
        assert!(offsets.libc_path.contains("libc"), "path should contain libc");
    }

    #[test]
    fn test_find_local_libc() {
        let (base, path) = find_local_libc().expect("should find local libc");
        assert!(base > 0, "base should be non-zero");
        assert!(path.contains("libc"), "path should contain libc");
    }

    #[test]
    fn test_is_libc_path() {
        assert!(is_libc_path("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(is_libc_path("/lib64/libc.so.6"));
        assert!(is_libc_path("/usr/lib/libc-2.31.so"));
        assert!(!is_libc_path("/lib/x86_64-linux-gnu/libpthread.so.0"));
        assert!(!is_libc_path("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"));
    }
}
