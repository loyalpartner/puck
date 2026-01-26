//! Bootstrap orchestration for library injection
//!
//! This module executes position-independent shellcode in the target process
//! to load libraries and call functions. The bootstrapper:
//! 1. Resolves libc symbols (dlopen, dlsym, pthread_create, etc.)
//! 2. Creates a new thread that performs dlopen + dlsym + function call
//!
//! This is a Frida-style two-stage injection:
//! - Stage 1: Bootstrap code runs in hijacked thread, resolves symbols
//! - Stage 2: New thread does dlopen/call (clean thread context, single dlopen reference)
//!
//! Supported architectures: x86_64, aarch64

pub mod context;

pub use context::{BootstrapContext, BootstrapMode, BootstrapStatus, LibcApi};

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

use crate::error::{Error, Result};
use crate::ptrace::TracedProcess;

/// Embedded bootstrapper shellcode (compiled from C bootstrapper)
#[cfg(target_arch = "x86_64")]
static BOOTSTRAPPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bootstrapper-x86_64.bin"));

#[cfg(target_arch = "aarch64")]
static BOOTSTRAPPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bootstrapper-aarch64.bin"));

/// Memory layout constants
const CODE_SIZE: u64 = 4096;
const CONTEXT_OFFSET: u64 = CODE_SIZE;
const CONTEXT_SIZE: u64 = 224;

/// String storage offsets (after context)
const PATH_OFFSET: u64 = CONTEXT_OFFSET + CONTEXT_SIZE;
const FUNC_OFFSET: u64 = PATH_OFFSET + 512; // PATH_SIZE = 512
const ARG_OFFSET: u64 = FUNC_OFFSET + 256; // FUNC_SIZE = 256

/// Stack region
const STACK_OFFSET: u64 = ARG_OFFSET + 512; // ARG_SIZE = 512
const STACK_SIZE: u64 = 4096;

/// Stack alignment requirement (16 bytes)
const STACK_ALIGNMENT: u64 = 16;

/// Result of bootstrap execution
#[derive(Debug)]
pub struct BootstrapResult {
    /// Handle returned by dlopen (for LOAD mode)
    pub handle: u64,
    /// Resolved libc API addresses
    pub libc: LibcApi,
}

/// Write null-terminated string to target memory
fn write_string(proc: &TracedProcess, addr: u64, s: &str) -> Result<()> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    proc.write_memory(addr, &bytes)
}

/// Parameters for bootstrap execution
struct BootstrapParams<'a> {
    library_or_pattern: &'a str,
    function_name: &'a str,
    argument: Option<&'a str>,
    mode: BootstrapMode,
    mode_label: &'static str,
}

/// Common bootstrap execution logic
fn execute_bootstrap(
    proc: &TracedProcess,
    mem: u64,
    params: BootstrapParams<'_>,
) -> Result<BootstrapResult> {
    // Verify bootstrapper fits in code region
    if BOOTSTRAPPER.len() as u64 > CODE_SIZE {
        return Err(Error::BootstrapFailed {
            status: BootstrapStatus::AuxvParseFailed,
            message: format!(
                "bootstrapper too large: {} bytes (max {})",
                BOOTSTRAPPER.len(),
                CODE_SIZE
            ),
        });
    }

    // Write bootstrapper code
    proc.write_memory(mem, BOOTSTRAPPER)?;

    // Calculate addresses
    let ctx_addr = mem + CONTEXT_OFFSET;
    let path_addr = mem + PATH_OFFSET;
    let func_addr = mem + FUNC_OFFSET;
    let arg_addr = mem + ARG_OFFSET;
    let stack_top = mem + STACK_OFFSET + STACK_SIZE;

    // Write strings to target memory
    write_string(proc, path_addr, params.library_or_pattern)?;
    write_string(proc, func_addr, params.function_name)?;
    if let Some(arg) = params.argument {
        write_string(proc, arg_addr, arg)?;
    } else {
        proc.write_memory(arg_addr, &[0u8])?;
    }

    // Initialize context
    let arg_ptr = if params.argument.is_some() { arg_addr } else { 0 };
    let ctx = match params.mode {
        BootstrapMode::Load => BootstrapContext::new_load(path_addr, func_addr, arg_ptr),
        BootstrapMode::Call => BootstrapContext::new_call(path_addr, func_addr, arg_ptr),
    };
    proc.write_memory(ctx_addr, &ctx.to_bytes())?;

    eprintln!(
        "[debug] bootstrapper @ 0x{:x} ({}), context @ 0x{:x}",
        mem, params.mode_label, ctx_addr
    );
    eprintln!(
        "[debug] library: {} @ 0x{:x}",
        params.library_or_pattern, path_addr
    );
    eprintln!("[debug] function: {} @ 0x{:x}", params.function_name, func_addr);

    // Set up registers for execution (architecture-specific)
    let mut regs = proc.saved_regs;

    #[cfg(target_arch = "x86_64")]
    {
        regs.rdi = ctx_addr;      // First argument
        regs.rip = mem;           // Instruction pointer
        regs.rsp = (stack_top & !(STACK_ALIGNMENT - 1)) - 8;
        regs.orig_rax = u64::MAX; // Prevent syscall restart
    }

    #[cfg(target_arch = "aarch64")]
    {
        regs.regs[0] = ctx_addr;  // First argument (x0)
        regs.pc = mem;            // Program counter
        regs.sp = stack_top & !(STACK_ALIGNMENT - 1);
    }

    proc.setregs(regs)?;
    ptrace::cont(proc.pid, None).map_err(Error::Ptrace)?;

    // Handle execution result
    match waitpid(proc.pid, None) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
            let ctx_bytes = proc.read_memory(ctx_addr, CONTEXT_SIZE as usize)?;
            let ctx = BootstrapContext::from_bytes(&ctx_bytes).ok_or_else(|| {
                Error::BootstrapFailed {
                    status: BootstrapStatus::AuxvParseFailed,
                    message: "failed to parse bootstrap context".to_string(),
                }
            })?;

            proc.setregs(proc.saved_regs)?;

            eprintln!("[debug] bootstrap status: {:?}", ctx.get_status());
            eprintln!("[debug] dlopen @ 0x{:x}", ctx.libc.dlopen);
            eprintln!("[debug] pthread_create @ 0x{:x}", ctx.libc.pthread_create);

            let status = ctx.get_status().unwrap_or(BootstrapStatus::AuxvParseFailed);
            if status != BootstrapStatus::Success {
                return Err(Error::BootstrapFailed {
                    status,
                    message: format!("{} failed with status: {:?}", params.mode_label, status),
                });
            }

            Ok(BootstrapResult {
                handle: ctx.handle,
                libc: ctx.libc,
            })
        }
        Ok(WaitStatus::Stopped(_, sig)) => {
            if let Ok(crash_regs) = ptrace::getregs(proc.pid) {
                #[cfg(target_arch = "x86_64")]
                {
                    eprintln!(
                        "[debug] crash at RIP=0x{:x}, RSP=0x{:x}",
                        crash_regs.rip, crash_regs.rsp
                    );
                    eprintln!(
                        "[debug] mem base=0x{:x}, offset=0x{:x}",
                        mem,
                        crash_regs.rip.wrapping_sub(mem)
                    );
                }
                #[cfg(target_arch = "aarch64")]
                {
                    eprintln!(
                        "[debug] crash at PC=0x{:x}, SP=0x{:x}",
                        crash_regs.pc, crash_regs.sp
                    );
                    eprintln!(
                        "[debug] mem base=0x{:x}, offset=0x{:x}",
                        mem,
                        crash_regs.pc.wrapping_sub(mem)
                    );
                }
            }
            proc.setregs(proc.saved_regs)?;
            Err(Error::BootstrapFailed {
                status: BootstrapStatus::AuxvParseFailed,
                message: format!("{} crashed with signal: {:?}", params.mode_label, sig),
            })
        }
        Ok(WaitStatus::Signaled(_, sig, _)) => Err(Error::BootstrapFailed {
            status: BootstrapStatus::AuxvParseFailed,
            message: format!("{} terminated with signal: {:?}", params.mode_label, sig),
        }),
        Ok(status) => {
            proc.setregs(proc.saved_regs)?;
            Err(Error::BootstrapFailed {
                status: BootstrapStatus::AuxvParseFailed,
                message: format!("unexpected wait status: {:?}", status),
            })
        }
        Err(e) => {
            let _ = proc.setregs(proc.saved_regs);
            Err(Error::Ptrace(e))
        }
    }
}

/// Execute the bootstrapper to load a library and call a function
///
/// This is a Frida-style injection that:
/// 1. Writes bootstrapper code to allocated memory
/// 2. Sets up context with library path, function name, and argument
/// 3. Executes bootstrapper which creates a new thread
/// 4. The new thread does dlopen + dlsym + call (single dlopen reference)
///
/// # Arguments
/// * `proc` - The traced process (must be attached and stopped)
/// * `mem` - Base address of allocated memory (must be RWX, at least 8KB)
/// * `library_path` - Path to the library to load
/// * `function_name` - Name of the function to call
/// * `argument` - Optional string argument to pass to the function
///
/// # Returns
/// `BootstrapResult` containing the dlopen handle and resolved libc addresses
pub fn inject_library(
    proc: &TracedProcess,
    mem: u64,
    library_path: &str,
    function_name: &str,
    argument: Option<&str>,
) -> Result<BootstrapResult> {
    execute_bootstrap(
        proc,
        mem,
        BootstrapParams {
            library_or_pattern: library_path,
            function_name,
            argument,
            mode: BootstrapMode::Load,
            mode_label: "LOAD",
        },
    )
}

/// Call a function in an already-loaded library
///
/// This uses CALL mode to find a library in the link_map and call a function.
///
/// # Arguments
/// * `proc` - The traced process (must be attached and stopped)
/// * `mem` - Base address of allocated memory
/// * `library_pattern` - Pattern to match library name in link_map
/// * `function_name` - Name of the function to call
/// * `argument` - Optional string argument to pass to the function
pub fn call_in_library(
    proc: &TracedProcess,
    mem: u64,
    library_pattern: &str,
    function_name: &str,
    argument: Option<&str>,
) -> Result<BootstrapResult> {
    execute_bootstrap(
        proc,
        mem,
        BootstrapParams {
            library_or_pattern: library_pattern,
            function_name,
            argument,
            mode: BootstrapMode::Call,
            mode_label: "CALL",
        },
    )
}

/// Get the size of the embedded bootstrapper shellcode
pub fn bootstrapper_size() -> usize {
    BOOTSTRAPPER.len()
}

/// Get required memory size for injection
pub fn required_memory_size() -> u64 {
    STACK_OFFSET + STACK_SIZE
}
