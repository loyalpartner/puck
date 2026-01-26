//! Code swap scope for temporary code execution
//!
//! When we cannot call libc mmap directly (e.g., static binaries, version mismatch),
//! we temporarily borrow executable memory to run shellcode.

use crate::elf::{parse_maps, MemoryMapping};
use crate::error::{Error, Result};
use crate::ptrace::TracedProcess;

/// Temporarily replace executable memory to run code
///
/// This is used as a fallback when we cannot call remote libc functions directly.
/// We find an executable region, save its contents, write our shellcode,
/// execute it, then restore the original contents.
pub struct ProcessCodeSwapScope<'a> {
    proc: &'a TracedProcess,
    code_addr: u64,
    original_code: Vec<u8>,
}

impl<'a> ProcessCodeSwapScope<'a> {
    /// Find executable region, save original code, write new code
    pub fn new(proc: &'a TracedProcess, code: &[u8]) -> Result<Self> {
        // Find a suitable executable region
        let maps = parse_maps(proc.pid.as_raw())?;
        let mapping = find_suitable_executable_region(&maps, code.len())?;

        // Use end of region to minimize impact on running code
        let code_addr = mapping.end - round_up(code.len() as u64, 16);

        // Save original code
        let original_code = proc.read_memory(code_addr, code.len())?;

        // Write new code
        proc.write_memory(code_addr, code)?;

        Ok(Self {
            proc,
            code_addr,
            original_code,
        })
    }

    /// Get the address where code was written
    pub fn code_addr(&self) -> u64 {
        self.code_addr
    }

    /// Restore original code
    pub fn revert(self) -> Result<()> {
        self.proc.write_memory(self.code_addr, &self.original_code)
    }
}

/// Find a suitable executable region for code injection
fn find_suitable_executable_region(maps: &[MemoryMapping], min_size: usize) -> Result<&MemoryMapping> {
    // Prefer libraries over vdso/vsyscall
    // Avoid memfd regions (might be special)
    let min_size = min_size as u64;

    // First pass: look for regular libraries
    for mapping in maps {
        if !mapping.perms.contains('x') || !mapping.perms.contains('r') {
            continue;
        }

        if let Some(ref path) = mapping.path {
            // Skip special mappings
            if path.starts_with("[vdso]")
                || path.starts_with("[vsyscall]")
                || path.starts_with("memfd:")
            {
                continue;
            }

            // Skip if region is too small
            if mapping.end - mapping.start < min_size {
                continue;
            }

            return Ok(mapping);
        }
    }

    // Fallback: try vdso (always present and executable)
    for mapping in maps {
        if !mapping.perms.contains('x') || !mapping.perms.contains('r') {
            continue;
        }

        if let Some(ref path) = mapping.path {
            if path.contains("[vdso]") && mapping.end - mapping.start >= min_size {
                return Ok(mapping);
            }
        }
    }

    Err(Error::NoExecutableMemory)
}

/// Round up to alignment
fn round_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Generate mmap shellcode for the target architecture
#[cfg(target_arch = "x86_64")]
pub fn generate_mmap_shellcode(size: u64) -> Vec<u8> {
    // x86_64 syscall:
    // rax = 9 (mmap)
    // rdi = addr (0)
    // rsi = length
    // rdx = prot (7 = RWX)
    // r10 = flags (0x22 = MAP_PRIVATE | MAP_ANONYMOUS)
    // r8 = fd (-1)
    // r9 = offset (0)
    // syscall
    // int3 (to stop execution)
    let mut code = Vec::new();

    // mov rax, 9
    code.extend_from_slice(&[0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00]);
    // xor rdi, rdi
    code.extend_from_slice(&[0x48, 0x31, 0xff]);
    // mov rsi, size
    code.extend_from_slice(&[0x48, 0xbe]);
    code.extend_from_slice(&size.to_le_bytes());
    // mov rdx, 7
    code.extend_from_slice(&[0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00]);
    // mov r10, 0x22
    code.extend_from_slice(&[0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00]);
    // mov r8, -1
    code.extend_from_slice(&[0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff]);
    // xor r9, r9
    code.extend_from_slice(&[0x4d, 0x31, 0xc9]);
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);
    // int3
    code.push(0xcc);

    code
}

#[cfg(target_arch = "aarch64")]
pub fn generate_mmap_shellcode(size: u64) -> Vec<u8> {
    // aarch64 syscall:
    // x8 = 222 (mmap)
    // x0 = addr (0)
    // x1 = length
    // x2 = prot (7 = RWX)
    // x3 = flags (0x22 = MAP_PRIVATE | MAP_ANONYMOUS)
    // x4 = fd (-1)
    // x5 = offset (0)
    // svc #0
    // brk #0 (to stop execution)
    let mut code = Vec::new();

    // mov x8, #222
    code.extend_from_slice(&[0xc8, 0x1b, 0x80, 0xd2]);
    // mov x0, #0
    code.extend_from_slice(&[0x00, 0x00, 0x80, 0xd2]);

    // Load size into x1 (may need multiple instructions for large values)
    // For simplicity, use movz + movk pattern
    let size_lo = (size & 0xFFFF) as u32;
    let size_hi1 = ((size >> 16) & 0xFFFF) as u32;
    let size_hi2 = ((size >> 32) & 0xFFFF) as u32;
    let size_hi3 = ((size >> 48) & 0xFFFF) as u32;

    // movz x1, #size_lo
    let movz = 0xd2800001 | (size_lo << 5);
    code.extend_from_slice(&movz.to_le_bytes());

    if size_hi1 != 0 {
        // movk x1, #size_hi1, lsl #16
        let movk = 0xf2a00001 | (size_hi1 << 5);
        code.extend_from_slice(&movk.to_le_bytes());
    }
    if size_hi2 != 0 {
        // movk x1, #size_hi2, lsl #32
        let movk = 0xf2c00001 | (size_hi2 << 5);
        code.extend_from_slice(&movk.to_le_bytes());
    }
    if size_hi3 != 0 {
        // movk x1, #size_hi3, lsl #48
        let movk = 0xf2e00001 | (size_hi3 << 5);
        code.extend_from_slice(&movk.to_le_bytes());
    }

    // mov x2, #7
    code.extend_from_slice(&[0xe2, 0x00, 0x80, 0xd2]);
    // mov x3, #0x22
    code.extend_from_slice(&[0x43, 0x04, 0x80, 0xd2]);
    // mov x4, #-1 (movn x4, #0)
    code.extend_from_slice(&[0x04, 0x00, 0x80, 0x92]);
    // mov x5, #0
    code.extend_from_slice(&[0x05, 0x00, 0x80, 0xd2]);
    // svc #0
    code.extend_from_slice(&[0x01, 0x00, 0x00, 0xd4]);
    // brk #0
    code.extend_from_slice(&[0x00, 0x00, 0x20, 0xd4]);

    code
}
