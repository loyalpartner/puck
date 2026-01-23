//! Library injection implementation
//!
//! This module provides the main `inject_library` function that injects
//! a shared library into a running process using ptrace.

use std::path::Path;
use nix::unistd::Pid;

use crate::call::{remote_call_with_shellcode_and_stack, remote_mmap};
use crate::elf::resolve_symbol_in_target;
use crate::error::{Error, Result};
use crate::ptrace::TracedProcess;

/// Result of a successful injection
#[derive(Debug)]
pub struct InjectionResult {
    /// The target process ID
    pub pid: i32,
    /// The handle returned by dlopen (can be used for dlsym)
    pub handle: u64,
}

/// Result of injection with function call
#[derive(Debug)]
pub struct InjectionCallResult {
    /// The target process ID
    pub pid: i32,
    /// The handle returned by dlopen
    pub handle: u64,
    /// The return value from the called function
    pub return_value: u64,
}

/// Inject a shared library into a running process
///
/// This function performs the following steps:
/// 1. Resolves the dlopen address in the target process
/// 2. Attaches to the process with ptrace
/// 3. Allocates RWX memory in the target using mmap syscall
/// 4. Writes the library path to the allocated memory
/// 5. Calls dlopen using shellcode injection
/// 6. Restores the process state and detaches
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
///
/// # Returns
/// `InjectionResult` containing the dlopen handle on success
///
/// # Errors
/// Returns an error if:
/// - The library path is invalid
/// - The target process doesn't exist or can't be attached
/// - dlopen fails in the target process
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_library;
///
/// let result = inject_library(1234, Path::new("/path/to/library.so")).unwrap();
/// println!("Injected! handle = 0x{:x}", result.handle);
/// ```
pub fn inject_library(pid: i32, library_path: &Path) -> Result<InjectionResult> {
    let lib_path_str = library_path
        .canonicalize()?
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid path encoding",
            ))
        })?
        .to_string();

    // Step 1: Resolve dlopen address in target process
    // Try __libc_dlopen_mode first (internal glibc function), fallback to dlopen
    let dlopen_addr = resolve_symbol_in_target(pid, "__libc_dlopen_mode")
        .or_else(|_| resolve_symbol_in_target(pid, "dlopen"))?;
    eprintln!("[debug] dlopen @ 0x{:x}", dlopen_addr);

    // Step 2: Attach to process
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;

    // Step 3: Allocate memory in target using mmap syscall
    // Layout: [0..256: path] [256..4096: stack space] [4096..8192: code]
    let mem_size = 8192u64;
    let remote_mem = remote_mmap(&proc, mem_size)?;

    // Step 4: Write library path to allocated memory
    let mut path_bytes = lib_path_str.as_bytes().to_vec();
    path_bytes.push(0);
    proc.write_memory(remote_mem, &path_bytes)?;

    // Step 5: Call dlopen
    let code_addr = remote_mem + 4096;

    eprintln!("[debug] calling dlopen({}, RTLD_NOW)...", lib_path_str);
    let handle = remote_call_with_shellcode_and_stack(
        &proc,
        dlopen_addr,
        &[remote_mem, libc::RTLD_NOW as u64],
        code_addr,
        None, // Use original stack
    )?;
    eprintln!("[debug] dlopen returned 0x{:x}", handle);

    // If dlopen failed, try to get error message via dlerror
    if handle == 0 {
        if let Ok(dlerror_addr) = resolve_symbol_in_target(pid, "dlerror") {
            if let Ok(err_ptr) = remote_call_with_shellcode_and_stack(&proc, dlerror_addr, &[], code_addr, None) {
                if err_ptr != 0 {
                    // Read error string from target
                    if let Ok(err_bytes) = proc.read_memory(err_ptr, 256) {
                        if let Some(end) = err_bytes.iter().position(|&b| b == 0) {
                            if let Ok(err_msg) = std::str::from_utf8(&err_bytes[..end]) {
                                eprintln!("[debug] dlerror: {}", err_msg);
                            }
                        }
                    }
                }
            }
        }
        proc.detach()?;
        return Err(Error::DlopenFailed {
            path: library_path.to_path_buf(),
        });
    }

    // Step 6: Restore registers and detach
    proc.detach()?;

    Ok(InjectionResult { pid, handle })
}

/// Inject a shared library and call a function with arguments
///
/// This extends `inject_library` by also calling a specified function
/// from the injected library with the provided arguments.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
/// * `function_name` - Name of the function to call after injection
/// * `args` - Arguments to pass to the function (up to 6 for x86_64)
///
/// # Returns
/// `InjectionCallResult` containing the handle and function return value
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_and_call;
///
/// // Inject and call: int my_func(int a, int b)
/// let result = inject_and_call(
///     1234,
///     Path::new("/path/to/library.so"),
///     "my_func",
///     &[42, 100],
/// ).unwrap();
/// println!("Function returned: {}", result.return_value);
/// ```
pub fn inject_and_call(
    pid: i32,
    library_path: &Path,
    function_name: &str,
    args: &[u64],
) -> Result<InjectionCallResult> {
    let lib_path_str = library_path
        .canonicalize()?
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid path encoding",
            ))
        })?
        .to_string();

    // Resolve dlopen and dlsym addresses
    // Try internal glibc functions first, then public ones
    let dlopen_addr = resolve_symbol_in_target(pid, "__libc_dlopen_mode")
        .or_else(|_| resolve_symbol_in_target(pid, "dlopen"))?;
    let dlsym_addr = resolve_symbol_in_target(pid, "__libc_dlsym")
        .or_else(|_| resolve_symbol_in_target(pid, "dlsym"))?;

    // Attach to process
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;

    // Allocate memory: [0..512: strings] [512..4096: stack] [4096..8192: code]
    let mem_size = 8192u64;
    let remote_mem = remote_mmap(&proc, mem_size)?;
    let code_addr = remote_mem + 4096;

    // Write library path at offset 0
    let mut path_bytes = lib_path_str.as_bytes().to_vec();
    path_bytes.push(0);
    proc.write_memory(remote_mem, &path_bytes)?;

    // Write function name at offset 256
    let func_name_addr = remote_mem + 256;
    let mut func_bytes = function_name.as_bytes().to_vec();
    func_bytes.push(0);
    proc.write_memory(func_name_addr, &func_bytes)?;

    // Step 1: Call dlopen
    eprintln!("[debug] calling dlopen({}, RTLD_NOW)...", lib_path_str);
    let handle = remote_call_with_shellcode_and_stack(
        &proc,
        dlopen_addr,
        &[remote_mem, libc::RTLD_NOW as u64],
        code_addr,
        None,
    )?;

    if handle == 0 {
        proc.detach()?;
        return Err(Error::DlopenFailed {
            path: library_path.to_path_buf(),
        });
    }
    eprintln!("[debug] dlopen returned 0x{:x}", handle);

    // Step 2: Call dlsym to find the function
    eprintln!("[debug] calling dlsym(0x{:x}, \"{}\")...", handle, function_name);
    let func_addr = remote_call_with_shellcode_and_stack(
        &proc,
        dlsym_addr,
        &[handle, func_name_addr],
        code_addr,
        None,
    )?;

    if func_addr == 0 {
        proc.detach()?;
        return Err(Error::SymbolNotFound {
            symbol: function_name.to_string(),
            path: library_path.display().to_string(),
        });
    }
    eprintln!("[debug] dlsym returned 0x{:x}", func_addr);

    // Step 3: Call the function with provided arguments
    eprintln!("[debug] calling {}({:?})...", function_name, args);
    let return_value = remote_call_with_shellcode_and_stack(
        &proc,
        func_addr,
        args,
        code_addr,
        None,
    )?;
    eprintln!("[debug] {} returned 0x{:x}", function_name, return_value);

    proc.detach()?;

    Ok(InjectionCallResult {
        pid,
        handle,
        return_value,
    })
}

/// Inject a shared library and call a function with a string argument
///
/// Similar to `inject_and_call`, but passes a string as the first argument
/// to the function. The string is written to the target process memory.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `library_path` - Path to the shared library to inject
/// * `function_name` - Name of the function to call (should accept `const char*`)
/// * `data` - String data to pass to the function
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use hsinject::inject_and_call_with_string;
///
/// // Inject and call: int init(const char* config)
/// let result = inject_and_call_with_string(
///     1234,
///     Path::new("/path/to/library.so"),
///     "init",
///     "window:0x5a00023",
/// ).unwrap();
/// ```
pub fn inject_and_call_with_string(
    pid: i32,
    library_path: &Path,
    function_name: &str,
    data: &str,
) -> Result<InjectionCallResult> {
    let lib_path_str = library_path
        .canonicalize()?
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid path encoding",
            ))
        })?
        .to_string();

    // Resolve dlopen and dlsym addresses
    let dlopen_addr = resolve_symbol_in_target(pid, "__libc_dlopen_mode")
        .or_else(|_| resolve_symbol_in_target(pid, "dlopen"))?;
    let dlsym_addr = resolve_symbol_in_target(pid, "__libc_dlsym")
        .or_else(|_| resolve_symbol_in_target(pid, "dlsym"))?;

    // Attach to process
    let proc = TracedProcess::attach(Pid::from_raw(pid))?;

    // Allocate memory:
    // [0..256: lib path] [256..512: func name] [512..1024: data string]
    // [1024..4096: stack] [4096..8192: code]
    let mem_size = 8192u64;
    let remote_mem = remote_mmap(&proc, mem_size)?;
    let code_addr = remote_mem + 4096;

    // Write library path at offset 0
    let mut path_bytes = lib_path_str.as_bytes().to_vec();
    path_bytes.push(0);
    proc.write_memory(remote_mem, &path_bytes)?;

    // Write function name at offset 256
    let func_name_addr = remote_mem + 256;
    let mut func_bytes = function_name.as_bytes().to_vec();
    func_bytes.push(0);
    proc.write_memory(func_name_addr, &func_bytes)?;

    // Write data string at offset 512
    let data_addr = remote_mem + 512;
    let mut data_bytes = data.as_bytes().to_vec();
    data_bytes.push(0);
    proc.write_memory(data_addr, &data_bytes)?;

    // Step 1: Call dlopen
    eprintln!("[debug] calling dlopen({}, RTLD_NOW)...", lib_path_str);
    let handle = remote_call_with_shellcode_and_stack(
        &proc,
        dlopen_addr,
        &[remote_mem, libc::RTLD_NOW as u64],
        code_addr,
        None,
    )?;

    if handle == 0 {
        proc.detach()?;
        return Err(Error::DlopenFailed {
            path: library_path.to_path_buf(),
        });
    }
    eprintln!("[debug] dlopen returned 0x{:x}", handle);

    // Step 2: Call dlsym to find the function
    eprintln!("[debug] calling dlsym(0x{:x}, \"{}\")...", handle, function_name);
    let func_addr = remote_call_with_shellcode_and_stack(
        &proc,
        dlsym_addr,
        &[handle, func_name_addr],
        code_addr,
        None,
    )?;

    if func_addr == 0 {
        proc.detach()?;
        return Err(Error::SymbolNotFound {
            symbol: function_name.to_string(),
            path: library_path.display().to_string(),
        });
    }
    eprintln!("[debug] dlsym returned 0x{:x}", func_addr);

    // Step 3: Call the function with string data pointer
    eprintln!("[debug] calling {}(\"{}\")...", function_name, data);
    let return_value = remote_call_with_shellcode_and_stack(
        &proc,
        func_addr,
        &[data_addr], // Pass pointer to string
        code_addr,
        None,
    )?;
    eprintln!("[debug] {} returned 0x{:x}", function_name, return_value);

    proc.detach()?;

    Ok(InjectionCallResult {
        pid,
        handle,
        return_value,
    })
}
