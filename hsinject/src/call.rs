//! Remote function call and syscall injection for process manipulation
//!
//! This module provides two main capabilities:
//! 1. `remote_syscall` - Execute syscalls in a target process via ptrace
//! 2. `remote_call_with_shellcode` - Call functions by injecting shellcode into executable memory

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

use crate::error::{Error, Result};
use crate::ptrace::TracedProcess;

/// Size of the red zone on x86_64 (128 bytes)
const RED_ZONE_SIZE: u64 = 128;

/// Stack alignment requirement (16 bytes)
const STACK_ALIGNMENT: u64 = 16;

/// Call a function in the remote process using shellcode injection
///
/// Instead of manipulating registers to call functions directly (which can have
/// issues with CET, TLS, etc.), we inject shellcode into executable memory
/// that performs the call and traps.
///
/// # Arguments
/// * `proc` - The traced process
/// * `func_addr` - Address of the function to call
/// * `args` - Function arguments (up to 6 for x86_64 ABI)
/// * `code_addr` - Address of executable memory to write shellcode
///
/// # Returns
/// The return value (RAX) of the called function
/// Call a function using shellcode with a custom stack
///
/// # Arguments
/// * `proc` - The traced process
/// * `func_addr` - Address of the function to call
/// * `args` - Function arguments (up to 6)
/// * `code_addr` - Address of executable memory for shellcode
/// * `stack_addr` - Optional custom stack address (top of stack region)
pub fn remote_call_with_shellcode(
    proc: &TracedProcess,
    func_addr: u64,
    args: &[u64],
    code_addr: u64,
) -> Result<u64> {
    remote_call_with_shellcode_and_stack(proc, func_addr, args, code_addr, None)
}

/// Call a function using shellcode with optional custom stack
pub fn remote_call_with_shellcode_and_stack(
    proc: &TracedProcess,
    func_addr: u64,
    args: &[u64],
    code_addr: u64,
    stack_top: Option<u64>,
) -> Result<u64> {
    let shellcode = build_call_shellcode(func_addr, args);
    proc.write_memory(code_addr, &shellcode)?;

    let mut regs = proc.saved_regs;

    // Use custom stack if provided, otherwise use original stack
    if let Some(stack) = stack_top {
        // Use provided stack, align to 16 bytes
        regs.rsp = stack & !(STACK_ALIGNMENT - 1);
    } else {
        // Use original stack with red zone
        regs.rsp -= RED_ZONE_SIZE;
        regs.rsp &= !(STACK_ALIGNMENT - 1);
    }

    regs.rip = code_addr;
    regs.orig_rax = u64::MAX;

    proc.setregs(regs)?;
    ptrace::cont(proc.pid, None).map_err(Error::Ptrace)?;

    match waitpid(proc.pid, None) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
            let result_regs = proc.getregs()?;
            proc.setregs(proc.saved_regs)?;
            Ok(result_regs.rax)
        }
        Ok(WaitStatus::Stopped(_, sig)) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::ProcessCrashed { signal: sig as i32 })
        }
        Ok(WaitStatus::Signaled(_, sig, _)) => {
            Err(Error::ProcessCrashed { signal: sig as i32 })
        }
        Ok(status) => {
            Err(Error::UnexpectedWaitStatus(format!("{:?}", status).len() as i32))
        }
        Err(e) => Err(Error::Ptrace(e)),
    }
}

/// Build x86_64 shellcode to call a function
fn build_call_shellcode(func_addr: u64, args: &[u64]) -> Vec<u8> {
    let mut code = Vec::new();

    // x86_64 calling convention: rdi, rsi, rdx, rcx, r8, r9
    // REX.W prefix + movabs opcode for each register
    const REG_OPCODES: &[[u8; 2]] = &[
        [0x48, 0xbf], // mov rdi, imm64
        [0x48, 0xbe], // mov rsi, imm64
        [0x48, 0xba], // mov rdx, imm64
        [0x48, 0xb9], // mov rcx, imm64
        [0x49, 0xb8], // mov r8, imm64
        [0x49, 0xb9], // mov r9, imm64
    ];

    for (i, &arg) in args.iter().take(6).enumerate() {
        code.extend_from_slice(&REG_OPCODES[i]);
        code.extend_from_slice(&arg.to_le_bytes());
    }

    // mov rax, func_addr
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&func_addr.to_le_bytes());

    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);

    // int3 (trap to return control)
    code.push(0xcc);

    code
}

/// Perform a syscall in the remote process using ptrace register injection
///
/// We find an existing syscall instruction in the process's memory and
/// set up registers to execute our desired syscall.
///
/// # Arguments
/// * `proc` - The traced process
/// * `syscall_num` - The syscall number (e.g., 9 for mmap)
/// * `args` - Syscall arguments (up to 6)
///
/// # Returns
/// The return value (RAX) of the syscall
pub fn remote_syscall(proc: &TracedProcess, syscall_num: u64, args: &[u64]) -> Result<u64> {
    // Set up registers for the syscall
    let mut regs = proc.saved_regs;
    regs.rax = syscall_num;
    regs.orig_rax = syscall_num;

    // Set arguments: rdi, rsi, rdx, r10, r8, r9
    // Note: syscall uses r10 instead of rcx for 4th argument
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

    // Find syscall instruction in existing executable memory
    let syscall_addr = find_syscall_instruction(proc.pid.as_raw())?;

    regs.rip = syscall_addr;
    proc.setregs(regs)?;

    // Single step to execute the syscall instruction
    ptrace::step(proc.pid, None).map_err(Error::Ptrace)?;

    match waitpid(proc.pid, None) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
            let result_regs = proc.getregs()?;

            // Restore original registers
            proc.setregs(proc.saved_regs)?;

            Ok(result_regs.rax)
        }
        Ok(WaitStatus::Stopped(_, sig)) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::ProcessCrashed { signal: sig as i32 })
        }
        Ok(status) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::UnexpectedWaitStatus(format!("{:?}", status).len() as i32))
        }
        Err(e) => {
            let _ = proc.setregs(proc.saved_regs);
            Err(Error::Ptrace(e))
        }
    }
}

/// Find a syscall instruction in the target process's executable memory
fn find_syscall_instruction(pid: i32) -> Result<u64> {
    use crate::elf::{parse_maps, MemoryMapping};

    let mappings = parse_maps(pid)?;

    // Helper to scan a mapping for syscall instruction (0x0f 0x05)
    let scan_for_syscall = |mapping: &MemoryMapping| -> Option<u64> {
        let scan_size = std::cmp::min(4096, (mapping.end - mapping.start) as usize);
        let data = read_process_memory(pid, mapping.start, scan_size).ok()?;

        data.windows(2)
            .position(|w| w == [0x0f, 0x05])
            .map(|i| mapping.start + i as u64)
    };

    let is_executable = |m: &MemoryMapping| m.perms.contains('x');

    // Check if mapping is a library (not vdso/vsyscall)
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

    // Fallback: try vdso which is guaranteed to have syscall instructions
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

/// Allocate memory in target process using mmap syscall
pub fn remote_mmap(proc: &TracedProcess, size: u64) -> Result<u64> {
    // SYS_mmap = 9
    // mmap(addr=0, length=size, prot=PROT_READ|PROT_WRITE|PROT_EXEC, flags=MAP_PRIVATE|MAP_ANONYMOUS, fd=-1, offset=0)
    let args = [
        0u64,        // addr = NULL
        size,        // length
        7u64,        // prot = PROT_READ|PROT_WRITE|PROT_EXEC
        0x22u64,     // flags = MAP_PRIVATE|MAP_ANONYMOUS
        u64::MAX,    // fd = -1 (as unsigned)
        0u64,        // offset = 0
    ];

    let result = remote_syscall(proc, 9, &args)?;

    // Check for MAP_FAILED (-1)
    if result == u64::MAX {
        return Err(Error::MmapFailed);
    }

    Ok(result)
}
