//! Process memory and maps parsing

use std::fs;

use crate::error::{Error, Result};

/// A memory mapping entry from /proc/pid/maps
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: Option<String>,
}

/// Parse /proc/<pid>/maps
pub fn parse_maps(pid: i32) -> Result<Vec<MemoryMapping>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::ProcessNotFound { pid }
        } else {
            Error::Io(e)
        }
    })?;

    let mut mappings = Vec::new();

    for line in content.lines() {
        if let Some(mapping) = parse_maps_line(line, pid)? {
            mappings.push(mapping);
        }
    }

    Ok(mappings)
}

fn parse_maps_line(line: &str, pid: i32) -> Result<Option<MemoryMapping>> {
    let mut parts = line.split_whitespace();

    // Address range: "7f1234000000-7f1234001000"
    let addr_range = parts.next().ok_or_else(|| Error::MapsParseError {
        pid,
        reason: "missing address range".into(),
    })?;

    let (start_str, end_str) = addr_range.split_once('-').ok_or_else(|| Error::MapsParseError {
        pid,
        reason: "invalid address range format".into(),
    })?;

    let start = u64::from_str_radix(start_str, 16).map_err(|_| Error::MapsParseError {
        pid,
        reason: format!("invalid start address: {}", start_str),
    })?;

    let end = u64::from_str_radix(end_str, 16).map_err(|_| Error::MapsParseError {
        pid,
        reason: format!("invalid end address: {}", end_str),
    })?;

    // Permissions: "r-xp"
    let perms = parts.next().ok_or_else(|| Error::MapsParseError {
        pid,
        reason: "missing permissions".into(),
    })?;

    // Offset: "00000000"
    let offset_str = parts.next().ok_or_else(|| Error::MapsParseError {
        pid,
        reason: "missing offset".into(),
    })?;

    let offset = u64::from_str_radix(offset_str, 16).map_err(|_| Error::MapsParseError {
        pid,
        reason: format!("invalid offset: {}", offset_str),
    })?;

    // Device: "00:00"
    let _device = parts.next();

    // Inode: "0"
    let _inode = parts.next();

    // Path (optional): "/lib/x86_64-linux-gnu/libc.so.6"
    let path = parts.next().map(|s| s.to_string());

    Ok(Some(MemoryMapping {
        start,
        end,
        perms: perms.to_string(),
        offset,
        path,
    }))
}

/// Find the base address of libc in the target process
pub fn find_libc_base(pid: i32) -> Result<u64> {
    let mappings = parse_maps(pid)?;

    for mapping in &mappings {
        if let Some(ref path) = mapping.path {
            // Match common libc patterns
            if (path.contains("libc.so") || path.contains("libc-"))
                && mapping.perms.contains('x')
                && mapping.offset == 0
            {
                return Ok(mapping.start);
            }
        }
    }

    Err(Error::LibcNotFound { pid })
}

/// Find a mapping by path pattern
pub fn find_mapping_by_path(pid: i32, pattern: &str) -> Result<Option<MemoryMapping>> {
    let mappings = parse_maps(pid)?;

    for mapping in mappings {
        if let Some(ref path) = mapping.path {
            if path.contains(pattern) {
                return Ok(Some(mapping));
            }
        }
    }

    Ok(None)
}

/// Get the path to libc in the current process
pub fn get_local_libc_path() -> Result<String> {
    let mappings = parse_maps(std::process::id() as i32)?;

    for mapping in &mappings {
        if let Some(ref path) = mapping.path {
            if (path.contains("libc.so") || path.contains("libc-"))
                && mapping.perms.contains('x')
            {
                return Ok(path.clone());
            }
        }
    }

    Err(Error::LibcNotFound { pid: std::process::id() as i32 })
}

/// Resolve a symbol address in the target process
///
/// This works by:
/// 1. Finding the symbol offset in our local libc
/// 2. Finding libc base in target process
/// 3. Adding offset to target base
pub fn resolve_symbol_in_target(pid: i32, symbol: &str) -> Result<u64> {
    // Get local libc info
    let local_libc_path = get_local_libc_path()?;
    let local_mappings = parse_maps(std::process::id() as i32)?;
    let local_libc_base = local_mappings
        .iter()
        .find(|m| m.path.as_ref() == Some(&local_libc_path) && m.offset == 0)
        .map(|m| m.start)
        .ok_or_else(|| Error::LibcNotFound { pid: std::process::id() as i32 })?;

    // Resolve symbol in local process using dlsym
    let symbol_cstr = std::ffi::CString::new(symbol).map_err(|_| Error::SymbolNotFound {
        symbol: symbol.to_string(),
        library: "libc".to_string(),
    })?;

    let local_addr = unsafe {
        let handle = libc::dlopen(std::ptr::null(), libc::RTLD_NOW);
        if handle.is_null() {
            return Err(Error::SymbolNotFound {
                symbol: symbol.to_string(),
                library: "libc".to_string(),
            });
        }
        let addr = libc::dlsym(handle, symbol_cstr.as_ptr());
        libc::dlclose(handle);
        addr as u64
    };

    if local_addr == 0 {
        return Err(Error::SymbolNotFound {
            symbol: symbol.to_string(),
            library: "libc".to_string(),
        });
    }

    // Calculate offset
    let offset = local_addr - local_libc_base;

    // Get target libc base
    let target_libc_base = find_libc_base(pid)?;

    // Calculate target address
    Ok(target_libc_base + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line = "7f8c5d200000-7f8c5d3c2000 r-xp 00000000 08:01 123456 /lib/x86_64-linux-gnu/libc.so.6";
        let mapping = parse_maps_line(line, 1).unwrap().unwrap();

        assert_eq!(mapping.start, 0x7f8c5d200000);
        assert_eq!(mapping.end, 0x7f8c5d3c2000);
        assert_eq!(mapping.perms, "r-xp");
        assert_eq!(mapping.offset, 0);
        assert_eq!(mapping.path, Some("/lib/x86_64-linux-gnu/libc.so.6".to_string()));
    }

    #[test]
    fn test_parse_maps_line_no_path() {
        let line = "7ffd5d200000-7ffd5d221000 rw-p 00000000 00:00 0";
        let mapping = parse_maps_line(line, 1).unwrap().unwrap();

        assert_eq!(mapping.start, 0x7ffd5d200000);
        assert_eq!(mapping.perms, "rw-p");
        assert_eq!(mapping.path, None);
    }

    #[test]
    fn test_get_local_libc_path() {
        let path = get_local_libc_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.contains("libc"));
    }
}
