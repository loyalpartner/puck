//! ELF parsing for symbol resolution (following Frida's approach)

use std::fs::File;
use std::path::Path;
use goblin::elf::Elf;
use memmap2::Mmap;

use crate::error::{Error, Result};

/// Find a symbol's offset in an ELF file by parsing the export table directly
pub fn find_symbol_offset(path: &Path, symbol_name: &str) -> Result<u64> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    let elf = Elf::parse(&mmap).map_err(|e| Error::ElfParse(e.to_string()))?;

    // Search in dynamic symbols (exported symbols)
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == symbol_name && sym.st_value != 0 {
                return Ok(sym.st_value);
            }
        }
    }

    Err(Error::SymbolNotFound {
        symbol: symbol_name.to_string(),
        path: path.display().to_string(),
    })
}

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

/// Find a library path and base address in a process by pattern
#[allow(dead_code)]
fn find_library(pid: i32, patterns: &[&str]) -> Result<(String, u64)> {
    let mappings = parse_maps(pid)?;

    for mapping in &mappings {
        if let Some(ref path) = mapping.path {
            if mapping.offset == 0 && patterns.iter().any(|p| path.contains(p)) {
                return Ok((path.clone(), mapping.start));
            }
        }
    }

    Err(Error::LibcNotFound { pid })
}

/// Find libc path and base address in a process
#[allow(dead_code)]
pub fn find_libc(pid: i32) -> Result<(String, u64)> {
    find_library(pid, &["libc.so", "libc-", "/libc.so.6"])
}

/// Find libdl path and base address in a process (for glibc < 2.34)
#[allow(dead_code)]
pub fn find_libdl(pid: i32) -> Result<(String, u64)> {
    find_library(pid, &["libdl.so", "libdl-"])
}

/// Find the base address of a library by looking at its executable segment
///
/// The base address is calculated by finding the r-xp (executable) segment
/// and subtracting its file offset. This is more reliable than looking for
/// offset=0 mappings because some systems create multiple mappings at offset 0.
fn find_library_base(mappings: &[MemoryMapping], lib_path: &str) -> Option<u64> {
    // First, try to find the executable segment (r-xp)
    for mapping in mappings {
        if let Some(ref path) = mapping.path {
            if path == lib_path && mapping.perms.contains('x') {
                // Calculate base by subtracting offset
                return Some(mapping.start - mapping.offset);
            }
        }
    }

    // Fallback: find the first r--p mapping with the smallest address
    // (in case there's no executable segment, though this shouldn't happen for .so files)
    mappings
        .iter()
        .filter(|m| m.path.as_ref() == Some(&lib_path.to_string()))
        .min_by_key(|m| m.start)
        .map(|m| m.start - m.offset)
}

/// Resolve a symbol address in a target process
///
/// This scans all loaded libraries in the target process to find the symbol,
/// similar to how Frida uses RTLD_DEFAULT. This handles cases like:
/// - glibc 2.34+: dlopen is in libc.so
/// - glibc < 2.34: dlopen is in libdl.so
pub fn resolve_symbol_in_target(pid: i32, symbol: &str) -> Result<u64> {
    let mappings = parse_maps(pid)?;

    // Collect unique library paths (from any mapping)
    let mut seen = std::collections::HashSet::new();
    let libraries: Vec<_> = mappings
        .iter()
        .filter_map(|m| m.path.as_ref().filter(|p| p.contains(".so")))
        .filter(|p| seen.insert(p.to_string()))
        .cloned()
        .collect();

    // Search each library for the symbol
    for lib_path in &libraries {
        if let Ok(offset) = find_symbol_offset(Path::new(lib_path), symbol) {
            // Find the correct base address for this library
            if let Some(base) = find_library_base(&mappings, lib_path) {
                return Ok(base + offset);
            }
        }
    }

    Err(Error::SymbolNotFound {
        symbol: symbol.to_string(),
        path: format!("process {}", pid),
    })
}
