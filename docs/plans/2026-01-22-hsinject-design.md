# hsinject Design Document

A Rust library for Linux process injection, inspired by Frida's injection mechanism.

## Overview

hsinject provides the ability to inject shared libraries or raw shellcode into running Linux processes using ptrace.

### Scope

- **Supported**: ptrace attach injection to running processes
- **Supported**: Shared library (.so) injection with optional entry point
- **Supported**: Raw shellcode injection
- **Supported**: x86_64 architecture (extensible to others)
- **Supported**: musl compilation
- **Not supported**: Spawn injection (LD_PRELOAD or fork+inject)

## Architecture

### Project Structure

```
hsinject/
├── Cargo.toml              # workspace
├── hsinject/               # High-level API (like frida-core)
│   └── src/
│       ├── lib.rs
│       ├── injector.rs
│       └── error.rs
│
├── hsinject-backend/       # Platform backend (like frida-gum)
│   └── src/
│       ├── lib.rs
│       ├── linux/
│       │   ├── mod.rs
│       │   ├── ptrace.rs
│       │   ├── inject.rs
│       │   ├── bootstrapper.rs
│       │   └── process.rs
│       └── arch/
│           ├── mod.rs
│           └── x86_64.rs
│
└── hsinject-cli/           # CLI tool
    └── src/main.rs
```

### Design Patterns (Following Frida)

1. **cfg conditional compilation** - Architecture-specific code selected at compile time
2. **Bootstrapper pattern** - Minimal shellcode that does dlopen → dlsym → call entry
3. **Breakpoint synchronization** - Use int3/brk to return control to injector
4. **Immediate detach** - Detach ptrace after injection completes

## Core API

```rust
// hsinject/src/lib.rs

pub enum Payload {
    Library(PathBuf),
    Shellcode(Vec<u8>),
}

pub struct InjectOptions {
    pub entry_point: Option<String>,
    pub argument: Option<String>,
}

pub struct InjectResult {
    pub pid: i32,
    pub handle: u64,
    pub retval: u64,
}

pub fn inject(
    pid: i32,
    payload: Payload,
    options: InjectOptions,
) -> Result<InjectResult>;
```

## Architecture Abstraction

Using cfg conditional compilation (Frida style):

```rust
// hsinject-backend/src/arch/mod.rs

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
```

Each architecture module exports:

```rust
// hsinject-backend/src/arch/x86_64.rs

pub type Regs = user_regs_struct;

pub fn get_ip(regs: &Regs) -> u64;
pub fn set_ip(regs: &mut Regs, addr: u64);
pub fn get_sp(regs: &Regs) -> u64;
pub fn set_syscall_args(regs: &mut Regs, num: u64, args: &[u64]);
pub fn get_syscall_result(regs: &Regs) -> u64;
pub fn get_return_value(regs: &Regs) -> u64;
pub fn bootstrapper_shellcode(params_addr: u64) -> Vec<u8>;

pub const SYSCALL_INSN: &[u8] = &[0x0f, 0x05];
pub const TRAP_INSN: &[u8] = &[0xcc];
```

## Ptrace Operations

```rust
// hsinject-backend/src/linux/ptrace.rs

pub struct TracedProcess {
    pid: Pid,
    saved_regs: Regs,
    attached: bool,
}

impl TracedProcess {
    pub fn attach(pid: Pid) -> Result<Self>;
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>>;
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<()>;
    pub fn execute_until_trap(&self, code_addr: u64) -> Result<Regs>;
    pub fn detach(self) -> Result<()>;
}
```

## Bootstrapper Design

The bootstrapper is a single shellcode that executes:

1. `handle = dlopen(lib_path, RTLD_NOW)`
2. `func = dlsym(handle, entry_point)` (if entry_point specified)
3. `retval = func(argument)` (if func found)
4. Store results to params struct
5. `int3` (return control to injector)

```rust
// hsinject-backend/src/linux/bootstrapper.rs

#[repr(C)]
pub struct BootstrapParams {
    pub dlopen_addr: u64,
    pub dlsym_addr: u64,
    pub lib_path_addr: u64,
    pub dlopen_flags: u64,
    pub entry_point_addr: u64,
    pub argument_addr: u64,
    pub result_handle: u64,
    pub result_retval: u64,
}
```

Memory layout for injection:

```
[0..64]      BootstrapParams struct
[64..256]    Bootstrapper shellcode
[256..512]   Library path string
[512..768]   Entry point name string
[768..1024]  Argument string
```

## Injection Flow

1. `ptrace(PTRACE_ATTACH)` + `waitpid`
2. Save original registers
3. Parse `/proc/<pid>/maps` to find libc base
4. Resolve `__libc_dlopen_mode` and `dlsym` addresses
5. Remote `mmap` to allocate memory in target
6. Write strings, params, and shellcode to remote memory
7. Set instruction pointer to shellcode address
8. `ptrace(PTRACE_CONT)` to execute
9. Wait for `SIGTRAP` (breakpoint)
10. Read results from params struct
11. Restore registers and `ptrace(PTRACE_DETACH)`

## Error Handling

```rust
// hsinject/src/error.rs

#[derive(Debug, Error)]
pub enum Error {
    // Ptrace errors
    AttachFailed { pid: i32, source: Errno },
    DetachFailed { pid: i32, source: Errno },
    MemReadFailed { addr: u64, source: Errno },
    MemWriteFailed { addr: u64, source: Errno },

    // Process state
    ProcessTerminated { pid: i32, signal: i32 },
    UnexpectedSignal { signal: i32 },
    ProcessNotFound { pid: i32 },

    // Symbol resolution
    LibcNotFound { pid: i32 },
    SymbolNotFound { symbol: String, library: String },

    // Injection
    MmapFailed { addr: u64 },
    DlopenFailed { path: PathBuf },
    DlsymFailed { symbol: String },

    // Permission
    PermissionDenied { pid: i32 },
}
```

## CLI Interface

```bash
# Inject shared library
hsinject -p <pid> -l ./libhook.so

# Inject with entry point
hsinject -p <pid> -l ./libhook.so -e my_init -a "config=debug"

# Inject shellcode
hsinject -p <pid> -s ./payload.bin

# Verbose output
hsinject -p <pid> -l ./libhook.so -v
```

## Dependencies

- `nix` - Safe ptrace and syscall wrappers
- `thiserror` - Error derive macro
- `clap` - CLI argument parsing
- `anyhow` - CLI error handling

## Testing Strategy

**Unit tests (80%)**:
- Architecture-specific code (registers, shellcode generation)
- Memory layout calculations
- Error conversion

**Integration tests (20%)**:
- Actual ptrace attach/detach
- Memory read/write
- Full injection (requires root + test library)

## Future Extensions

- [ ] aarch64 support
- [ ] arm (32-bit) support
- [ ] x86 (32-bit) support
- [ ] mips support
