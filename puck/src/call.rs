//! Remote function call and syscall injection for process manipulation
//!
//! This module provides multiple strategies for executing code in a target process:
//! 1. Find syscall instruction + SINGLESTEP (original, most reliable)
//! 2. Frida-style function call with dummy return address
//! 3. Shellcode via ProcessCodeSwapScope fallback
//!
//! Supports x86_64 and aarch64 architectures.

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

use crate::code_swap::{generate_mmap_shellcode, ProcessCodeSwapScope};
use crate::error::{Error, Result};
use crate::libc_resolver::{find_remote_libc_base, LibcOffsets};
use crate::ptrace::TracedProcess;

/// Syscall numbers (architecture-specific)
#[cfg(target_arch = "x86_64")]
mod syscall_nr {
    pub const MMAP: u64 = 9;
}

#[cfg(target_arch = "aarch64")]
mod syscall_nr {
    pub const MMAP: u64 = 222;
}

/// Dummy return address that will trigger SIGSEGV when function returns
/// Used for Frida-style function calls
const DUMMY_RETURN_ADDRESS: u64 = 0x320;

// ============================================================================
// Architecture helpers
// ============================================================================

/// Get return value from registers (architecture-specific)
#[cfg(target_arch = "x86_64")]
fn get_return_value(regs: &libc::user_regs_struct) -> u64 {
    regs.rax
}

#[cfg(target_arch = "aarch64")]
fn get_return_value(regs: &libc::user_regs_struct) -> u64 {
    regs.regs[0]
}

/// Get program counter from registers (architecture-specific)
#[cfg(target_arch = "x86_64")]
fn get_pc(regs: &libc::user_regs_struct) -> u64 {
    regs.rip
}

#[cfg(target_arch = "aarch64")]
fn get_pc(regs: &libc::user_regs_struct) -> u64 {
    regs.pc
}

/// Handle wait status after ptrace operation, returning the result value
fn handle_wait_result(proc: &TracedProcess, expected_signal: Signal) -> Result<u64> {
    match waitpid(proc.pid, None) {
        Ok(WaitStatus::Stopped(_, sig)) if sig == expected_signal => {
            let result_regs = proc.getregs()?;
            proc.setregs(proc.saved_regs)?;
            Ok(get_return_value(&result_regs))
        }
        Ok(WaitStatus::Stopped(_, sig)) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::ProcessCrashed { signal: sig as i32 })
        }
        Ok(status) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::UnexpectedWaitStatus(format!("{status:?}").len() as i32))
        }
        Err(e) => {
            let _ = proc.setregs(proc.saved_regs);
            Err(Error::Ptrace(e))
        }
    }
}

// ============================================================================
// Original syscall approach (most reliable)
// ============================================================================

/// Perform a syscall in the remote process using ptrace register injection
///
/// We find an existing syscall instruction in the process's memory and
/// set up registers to execute our desired syscall via SINGLESTEP.
pub fn remote_syscall(proc: &TracedProcess, syscall_num: u64, args: &[u64]) -> Result<u64> {
    let mut regs = proc.saved_regs;

    #[cfg(target_arch = "x86_64")]
    {
        regs.rax = syscall_num;
        regs.orig_rax = syscall_num;

        // Set arguments: rdi, rsi, rdx, r10, r8, r9
        let reg_refs: [&mut u64; 6] = [
            &mut regs.rdi,
            &mut regs.rsi,
            &mut regs.rdx,
            &mut regs.r10,
            &mut regs.r8,
            &mut regs.r9,
        ];

        for (reg, &arg) in reg_refs.into_iter().zip(args.iter()) {
            *reg = arg;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        regs.regs[8] = syscall_num; // x8 = syscall number

        // Set arguments: x0-x5
        for (i, &arg) in args.iter().take(6).enumerate() {
            regs.regs[i] = arg;
        }
    }

    // Find syscall instruction in existing executable memory
    let syscall_addr = find_syscall_instruction(proc.pid.as_raw())?;

    #[cfg(target_arch = "x86_64")]
    {
        regs.rip = syscall_addr;
    }

    #[cfg(target_arch = "aarch64")]
    {
        regs.pc = syscall_addr;
    }

    proc.setregs(regs)?;

    // Single step to execute the syscall instruction
    ptrace::step(proc.pid, None).map_err(Error::Ptrace)?;

    handle_wait_result(proc, Signal::SIGTRAP)
}

/// Find a syscall instruction in the target process's executable memory
fn find_syscall_instruction(pid: i32) -> Result<u64> {
    use crate::elf::{parse_maps, MemoryMapping};

    let mappings = parse_maps(pid)?;

    // Syscall instruction bytes (architecture-specific)
    #[cfg(target_arch = "x86_64")]
    const SYSCALL_BYTES: &[u8] = &[0x0f, 0x05]; // syscall

    #[cfg(target_arch = "aarch64")]
    const SYSCALL_BYTES: &[u8] = &[0x01, 0x00, 0x00, 0xd4]; // svc #0 (little-endian)

    let scan_for_syscall = |mapping: &MemoryMapping| -> Option<u64> {
        let scan_size = std::cmp::min(4096, (mapping.end - mapping.start) as usize);
        let data = read_process_memory(pid, mapping.start, scan_size).ok()?;

        #[cfg(target_arch = "aarch64")]
        {
            for i in (0..data.len().saturating_sub(3)).step_by(4) {
                if &data[i..i + 4] == SYSCALL_BYTES {
                    return Some(mapping.start + i as u64);
                }
            }
            None
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            data.windows(SYSCALL_BYTES.len())
                .position(|w| w == SYSCALL_BYTES)
                .map(|i| mapping.start + i as u64)
        }
    };

    let is_executable = |m: &MemoryMapping| m.perms.contains('x');

    let is_library = |path: &str| {
        !path.contains("[vdso]")
            && !path.contains("[vsyscall]")
            && (path.contains(".so") || path.contains("libc") || path.contains("ld-linux"))
    };

    // First pass: look for syscall in libraries
    for mapping in mappings.iter().filter(|m| is_executable(m)) {
        if let Some(ref path) = mapping.path {
            if is_library(path) {
                if let Some(addr) = scan_for_syscall(mapping) {
                    return Ok(addr);
                }
            }
        }
    }

    // Fallback: try vdso
    for mapping in mappings.iter().filter(|m| is_executable(m)) {
        if let Some(ref path) = mapping.path {
            if path.contains("[vdso]") {
                if let Some(addr) = scan_for_syscall(mapping) {
                    return Ok(addr);
                }
            }
        }
    }

    Err(Error::SymbolNotFound {
        symbol: "syscall instruction".to_string(),
        path: "process memory".to_string(),
    })
}

/// Read memory from a process using /proc/pid/mem
fn read_process_memory(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = File::open(&mem_path)?;
    file.seek(SeekFrom::Start(addr))?;

    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;

    Ok(buf)
}

// ============================================================================
// Frida-style remote function call
// ============================================================================

/// Call a function in the remote process (Frida-style)
///
/// Sets up registers for function call, uses dummy return address,
/// continues execution until SIGSEGV indicates function returned.
fn remote_call(proc: &TracedProcess, func_addr: u64, args: &[u64]) -> Result<u64> {
    let mut regs = proc.saved_regs;

    #[cfg(target_arch = "x86_64")]
    {
        let arg_regs: [&mut u64; 6] = [
            &mut regs.rdi,
            &mut regs.rsi,
            &mut regs.rdx,
            &mut regs.rcx,
            &mut regs.r8,
            &mut regs.r9,
        ];

        for (reg, &arg) in arg_regs.into_iter().zip(args.iter()) {
            *reg = arg;
        }

        regs.rsp = (regs.rsp & !0xF) - 8;
        proc.write_memory(regs.rsp, &DUMMY_RETURN_ADDRESS.to_le_bytes())?;
        regs.rip = func_addr;
    }

    #[cfg(target_arch = "aarch64")]
    {
        for (i, &arg) in args.iter().take(8).enumerate() {
            regs.regs[i] = arg;
        }
        regs.regs[30] = DUMMY_RETURN_ADDRESS;
        regs.sp = regs.sp & !0xF;
        regs.pc = func_addr;
    }

    proc.setregs(regs)?;
    ptrace::cont(proc.pid, None).map_err(Error::Ptrace)?;

    match waitpid(proc.pid, None) {
        Ok(WaitStatus::Stopped(_, Signal::SIGSEGV)) => {
            let result_regs = proc.getregs()?;

            // Verify we hit the dummy return address (expected SIGSEGV)
            if get_pc(&result_regs) != DUMMY_RETURN_ADDRESS {
                proc.setregs(proc.saved_regs)?;
                return Err(Error::ProcessCrashed { signal: 11 });
            }

            proc.setregs(proc.saved_regs)?;
            Ok(get_return_value(&result_regs))
        }
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
            let result_regs = proc.getregs()?;
            proc.setregs(proc.saved_regs)?;
            Ok(get_return_value(&result_regs))
        }
        Ok(WaitStatus::Stopped(_, sig)) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::ProcessCrashed { signal: sig as i32 })
        }
        Ok(status) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::UnexpectedWaitStatus(format!("{status:?}").len() as i32))
        }
        Err(e) => {
            let _ = proc.setregs(proc.saved_regs);
            Err(Error::Ptrace(e))
        }
    }
}

// ============================================================================
// Shellcode execution fallback
// ============================================================================

/// Execute shellcode that was written to process memory
fn execute_shellcode(proc: &TracedProcess, code_addr: u64) -> Result<u64> {
    let mut regs = proc.saved_regs;

    #[cfg(target_arch = "x86_64")]
    {
        regs.rip = code_addr;
    }

    #[cfg(target_arch = "aarch64")]
    {
        regs.pc = code_addr;
    }

    proc.setregs(regs)?;
    ptrace::cont(proc.pid, None).map_err(Error::Ptrace)?;

    handle_wait_result(proc, Signal::SIGTRAP)
}

// ============================================================================
// Public API
// ============================================================================

/// Allocate memory in target process using mmap
///
/// Tries multiple approaches in order:
/// 1. Direct syscall via SINGLESTEP (most reliable)
/// 2. Shellcode via ProcessCodeSwapScope (if syscall instruction not found)
/// 3. Call remote libc mmap (if libc versions match)
pub fn remote_mmap(proc: &TracedProcess, size: u64) -> Result<u64> {
    // Primary method: Direct syscall (most reliable)
    if let Ok(result) = try_syscall_mmap(proc, size) {
        return Ok(result);
    }

    // Fallback 1: Shellcode
    if let Ok(result) = try_shellcode_mmap(proc, size) {
        return Ok(result);
    }

    // Fallback 2: Call remote libc mmap
    try_libc_mmap(proc, size)
}

/// Try mmap via direct syscall (original approach)
fn try_syscall_mmap(proc: &TracedProcess, size: u64) -> Result<u64> {
    let args = [
        0u64,        // addr = NULL
        size,        // length
        7u64,        // prot = PROT_READ|PROT_WRITE|PROT_EXEC
        0x22u64,     // flags = MAP_PRIVATE|MAP_ANONYMOUS
        u64::MAX,    // fd = -1
        0u64,        // offset = 0
    ];

    let result = remote_syscall(proc, syscall_nr::MMAP, &args)?;

    if result == u64::MAX {
        return Err(Error::MmapFailed);
    }

    Ok(result)
}

/// Try mmap via shellcode
fn try_shellcode_mmap(proc: &TracedProcess, size: u64) -> Result<u64> {
    let shellcode = generate_mmap_shellcode(size);
    let swap = ProcessCodeSwapScope::new(proc, &shellcode)?;
    let result = execute_shellcode(proc, swap.code_addr())?;
    swap.revert()?;

    if result == u64::MAX {
        return Err(Error::MmapFailed);
    }

    Ok(result)
}

/// Try mmap via remote libc function call
fn try_libc_mmap(proc: &TracedProcess, size: u64) -> Result<u64> {
    let offsets = LibcOffsets::get()?;
    let remote_base = find_remote_libc_base(proc.pid.as_raw(), &offsets.libc_path)?;
    let remote_mmap = remote_base + offsets.mmap_offset;

    let args = [
        0u64,        // addr = NULL
        size,        // length
        7u64,        // prot = PROT_READ|PROT_WRITE|PROT_EXEC
        0x22u64,     // flags = MAP_PRIVATE|MAP_ANONYMOUS
        u64::MAX,    // fd = -1
        0u64,        // offset = 0
    ];

    let result = remote_call(proc, remote_mmap, &args)?;

    if result == u64::MAX {
        return Err(Error::MmapFailed);
    }

    Ok(result)
}
