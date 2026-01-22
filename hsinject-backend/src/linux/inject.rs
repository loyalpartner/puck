//! High-level injection logic

use std::path::Path;
use nix::unistd::Pid;

use crate::arch;
use crate::error::{Error, Result};
use crate::linux::bootstrapper::{BootstrapParams, layout};
use crate::linux::process::resolve_symbol_in_target;
use crate::linux::ptrace::TracedProcess;

/// Result of a successful injection
#[derive(Debug)]
pub struct InjectionResult {
    /// Target process ID
    pub pid: i32,
    /// dlopen handle
    pub handle: u64,
    /// Entry point return value
    pub retval: u64,
    /// Address of allocated remote memory (for debugging)
    pub remote_mem: u64,
}

/// Inject a shared library into a running process
pub fn inject_library(
    pid: i32,
    library_path: &Path,
    entry_point: Option<&str>,
    argument: Option<&str>,
) -> Result<InjectionResult> {
    // Validate inputs
    let lib_path_str = library_path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(library_path.to_path_buf()))?;

    if lib_path_str.len() >= layout::MAX_PATH_LEN {
        return Err(Error::PathTooLong {
            max: layout::MAX_PATH_LEN,
            actual: lib_path_str.len(),
        });
    }

    if let Some(ep) = entry_point {
        if ep.len() >= layout::MAX_ENTRY_POINT_LEN {
            return Err(Error::EntryPointTooLong {
                max: layout::MAX_ENTRY_POINT_LEN,
            });
        }
    }

    if let Some(arg) = argument {
        if arg.len() >= layout::MAX_ARGUMENT_LEN {
            return Err(Error::ArgumentTooLong {
                max: layout::MAX_ARGUMENT_LEN,
            });
        }
    }

    // Attach to process
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;

    // Resolve symbols in target
    let dlopen_addr = resolve_symbol_in_target(pid, "__libc_dlopen_mode")?;
    let dlsym_addr = resolve_symbol_in_target(pid, "dlsym")?;

    // Allocate remote memory via mmap syscall
    let remote_mem = remote_mmap(&proc, layout::TOTAL_SIZE as usize)?;

    // Calculate addresses
    let params_addr = remote_mem + layout::PARAMS_OFFSET;
    let code_addr = remote_mem + layout::CODE_OFFSET;
    let lib_path_addr = remote_mem + layout::LIB_PATH_OFFSET;
    let entry_point_str_addr = remote_mem + layout::ENTRY_POINT_OFFSET;
    let argument_str_addr = remote_mem + layout::ARGUMENT_OFFSET;

    // Write library path
    write_string(&proc, lib_path_addr, lib_path_str)?;

    // Write entry point if provided
    let entry_point_addr = if let Some(ep) = entry_point {
        write_string(&proc, entry_point_str_addr, ep)?;
        entry_point_str_addr
    } else {
        0
    };

    // Write argument if provided
    let argument_addr = if let Some(arg) = argument {
        write_string(&proc, argument_str_addr, arg)?;
        argument_str_addr
    } else {
        0
    };

    // Build params
    let params = BootstrapParams {
        dlopen_addr,
        dlsym_addr,
        lib_path_addr,
        dlopen_flags: libc::RTLD_NOW as u64,
        entry_point_addr,
        argument_addr,
        result_handle: 0,
        result_retval: 0,
    };

    // Write params
    proc.write_memory(params_addr, params.as_bytes())?;

    // Generate and write shellcode
    let shellcode = arch::bootstrapper_shellcode(params_addr);
    proc.write_memory(code_addr, &shellcode)?;

    // Execute shellcode
    let _result_regs = proc.execute_until_trap(code_addr)?;

    // Read back results
    let result_bytes = proc.read_memory(params_addr, BootstrapParams::SIZE)?;
    let result_params = BootstrapParams::from_bytes(&result_bytes)
        .ok_or_else(|| Error::MapsParseError {
            pid,
            reason: "failed to read bootstrap params".into(),
        })?;

    if result_params.result_handle == 0 {
        return Err(Error::DlopenFailed {
            path: library_path.to_path_buf(),
        });
    }

    // Detach
    proc.detach()?;

    Ok(InjectionResult {
        pid,
        handle: result_params.result_handle,
        retval: result_params.result_retval,
        remote_mem,
    })
}

/// Inject raw shellcode into a running process
pub fn inject_shellcode(pid: i32, shellcode: &[u8]) -> Result<InjectionResult> {
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;

    // Allocate remote memory
    let size = shellcode.len().max(4096);
    let remote_mem = remote_mmap(&proc, size)?;

    // Write shellcode
    proc.write_memory(remote_mem, shellcode)?;

    // Execute
    let result_regs = proc.execute_until_trap(remote_mem)?;

    // Detach
    proc.detach()?;

    Ok(InjectionResult {
        pid,
        handle: 0,
        retval: arch::get_return_value(&result_regs),
        remote_mem,
    })
}

/// Allocate memory in the target process using mmap syscall
fn remote_mmap(proc: &TracedProcess, size: usize) -> Result<u64> {
    // Build mmap shellcode
    let mut code = Vec::new();

    // Set up mmap syscall arguments
    let mmap_args = [
        0u64,                                            // addr = NULL
        size as u64,                                     // length
        (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64, // prot
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64, // flags
        u64::MAX,                                        // fd = -1
        0u64,                                            // offset
    ];

    // movabs rax, SYS_mmap (9)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&9u64.to_le_bytes());

    // movabs rdi, addr
    code.extend_from_slice(&[0x48, 0xbf]);
    code.extend_from_slice(&mmap_args[0].to_le_bytes());

    // movabs rsi, length
    code.extend_from_slice(&[0x48, 0xbe]);
    code.extend_from_slice(&mmap_args[1].to_le_bytes());

    // movabs rdx, prot
    code.extend_from_slice(&[0x48, 0xba]);
    code.extend_from_slice(&mmap_args[2].to_le_bytes());

    // movabs r10, flags
    code.extend_from_slice(&[0x49, 0xba]);
    code.extend_from_slice(&mmap_args[3].to_le_bytes());

    // movabs r8, fd
    code.extend_from_slice(&[0x49, 0xb8]);
    code.extend_from_slice(&mmap_args[4].to_le_bytes());

    // movabs r9, offset
    code.extend_from_slice(&[0x49, 0xb9]);
    code.extend_from_slice(&mmap_args[5].to_le_bytes());

    // syscall
    code.extend_from_slice(arch::SYSCALL_INSN);

    // int3
    code.push(0xcc);

    // Find a place to write the shellcode (use stack area temporarily)
    let regs = proc.getregs()?;
    let temp_addr = arch::get_sp(&regs) - 256;

    // Save original bytes
    let orig_bytes = proc.read_memory(temp_addr, code.len())?;

    // Write mmap shellcode
    proc.write_memory(temp_addr, &code)?;

    // Execute
    let result_regs = proc.execute_until_trap(temp_addr)?;

    // Restore original bytes
    proc.write_memory(temp_addr, &orig_bytes)?;

    // Get result
    let addr = arch::get_syscall_result(&result_regs);

    // Check for error (mmap returns -1 on failure)
    if addr as i64 == -1 || addr == 0 {
        return Err(Error::MmapFailed { addr });
    }

    Ok(addr)
}

/// Write a null-terminated string to remote memory
fn write_string(proc: &TracedProcess, addr: u64, s: &str) -> Result<()> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0); // null terminator
    proc.write_memory(addr, &bytes)
}
