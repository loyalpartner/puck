//! ELF parsing utilities for process memory inspection

use crate::error::{Error, Result};

/// Memory mapping info from /proc/pid/maps
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub perms: String,
    pub path: Option<String>,
}

/// Parse /proc/<pid>/maps to find memory mappings
pub fn parse_maps(pid: i32) -> Result<Vec<MemoryMapping>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::ProcessNotFound { pid }
        } else {
            Error::Io(e)
        }
    })?;

    let mappings = content.lines().filter_map(parse_maps_line).collect();
    Ok(mappings)
}

fn parse_maps_line(line: &str) -> Option<MemoryMapping> {
    let mut parts = line.split_whitespace();

    let addr_range = parts.next()?;
    let (start_str, end_str) = addr_range.split_once('-')?;

    let start = u64::from_str_radix(start_str, 16).ok()?;
    let end = u64::from_str_radix(end_str, 16).ok()?;

    let perms = parts.next()?.to_string();
    let offset_str = parts.next()?;
    let offset = u64::from_str_radix(offset_str, 16).ok()?;

    let _device = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.next().map(|s| s.to_string());

    Some(MemoryMapping { start, end, offset, perms, path })
}
