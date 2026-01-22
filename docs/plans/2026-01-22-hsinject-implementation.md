# hsinject Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust library for Linux process injection using ptrace, supporting shared library and shellcode injection.

**Architecture:** Workspace with 3 crates: `hsinject` (high-level API), `hsinject-backend` (ptrace/arch), `hsinject-cli` (CLI tool). Uses cfg conditional compilation for architecture abstraction following Frida's design.

**Tech Stack:** Rust, nix (ptrace), thiserror (errors), clap (CLI), libc

---

## Task 1: Workspace Setup

**Files:**
- Create: `Cargo.toml`
- Create: `hsinject/Cargo.toml`
- Create: `hsinject/src/lib.rs`
- Create: `hsinject-backend/Cargo.toml`
- Create: `hsinject-backend/src/lib.rs`
- Create: `hsinject-cli/Cargo.toml`
- Create: `hsinject-cli/src/main.rs`

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "hsinject",
    "hsinject-backend",
    "hsinject-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
authors = ["hsinject contributors"]

[workspace.dependencies]
hsinject = { path = "hsinject" }
hsinject-backend = { path = "hsinject-backend" }
nix = { version = "0.29", features = ["ptrace", "signal", "process"] }
libc = "0.2"
thiserror = "2"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
```

**Step 2: Create hsinject/Cargo.toml**

```toml
[package]
name = "hsinject"
version.workspace = true
edition.workspace = true

[dependencies]
hsinject-backend = { workspace = true }
thiserror = { workspace = true }
```

**Step 3: Create hsinject/src/lib.rs (stub)**

```rust
//! hsinject - Linux process injection library

pub use hsinject_backend::error::{Error, Result};

use std::path::PathBuf;

/// Injection payload
pub enum Payload {
    /// Shared library (.so) path
    Library(PathBuf),
    /// Raw shellcode bytes
    Shellcode(Vec<u8>),
}

/// Injection options
#[derive(Default)]
pub struct InjectOptions {
    /// Entry point function name (for library injection)
    pub entry_point: Option<String>,
    /// Argument to pass to entry point
    pub argument: Option<String>,
}

/// Injection result
pub struct InjectResult {
    /// Target process ID
    pub pid: i32,
    /// dlopen handle (for library injection)
    pub handle: u64,
    /// Entry point return value
    pub retval: u64,
}

/// Inject payload into a running process
pub fn inject(pid: i32, payload: Payload, options: InjectOptions) -> Result<InjectResult> {
    todo!()
}
```

**Step 4: Create hsinject-backend/Cargo.toml**

```toml
[package]
name = "hsinject-backend"
version.workspace = true
edition.workspace = true

[dependencies]
nix = { workspace = true }
libc = { workspace = true }
thiserror = { workspace = true }
```

**Step 5: Create hsinject-backend/src/lib.rs (stub)**

```rust
//! hsinject-backend - Platform-specific injection implementation

pub mod error;
pub mod arch;

#[cfg(target_os = "linux")]
pub mod linux;
```

**Step 6: Create hsinject-cli/Cargo.toml**

```toml
[package]
name = "hsinject-cli"
version.workspace = true
edition.workspace = true

[[bin]]
name = "hsinject"
path = "src/main.rs"

[dependencies]
hsinject = { workspace = true }
clap = { workspace = true }
anyhow = { workspace = true }
```

**Step 7: Create hsinject-cli/src/main.rs (stub)**

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "hsinject")]
#[command(about = "Inject shared libraries or shellcode into running processes")]
struct Cli {
    /// Target process ID
    #[arg(short, long)]
    pid: i32,
}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    println!("hsinject stub");
    Ok(())
}
```

**Step 8: Verify workspace builds**

Run: `cargo build`
Expected: Build succeeds with warnings about unused code

**Step 9: Commit**

```bash
git add -A
git commit -m "feat: initialize workspace structure

- hsinject: high-level API crate
- hsinject-backend: platform-specific implementation
- hsinject-cli: command-line tool"
```

---

## Task 2: Error Types

**Files:**
- Create: `hsinject-backend/src/error.rs`

**Step 1: Create error module**

```rust
//! Error types for hsinject

use std::path::PathBuf;
use nix::errno::Errno;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // === Ptrace ===
    #[error("failed to attach to process {pid}: {source}")]
    AttachFailed { pid: i32, source: Errno },

    #[error("failed to detach from process {pid}: {source}")]
    DetachFailed { pid: i32, source: Errno },

    #[error("failed to get/set registers: {0}")]
    RegAccessFailed(Errno),

    #[error("failed to read memory at 0x{addr:x}: {source}")]
    MemReadFailed { addr: u64, source: Errno },

    #[error("failed to write memory at 0x{addr:x}: {source}")]
    MemWriteFailed { addr: u64, source: Errno },

    // === Process state ===
    #[error("process {pid} terminated with signal {signal}")]
    ProcessTerminated { pid: i32, signal: i32 },

    #[error("unexpected signal {signal}, expected SIGTRAP")]
    UnexpectedSignal { signal: i32 },

    #[error("process {pid} not found")]
    ProcessNotFound { pid: i32 },

    #[error("timeout waiting for process {pid}")]
    Timeout { pid: i32 },

    // === Symbol resolution ===
    #[error("libc not found in process {pid}")]
    LibcNotFound { pid: i32 },

    #[error("symbol '{symbol}' not found in {library}")]
    SymbolNotFound { symbol: String, library: String },

    #[error("failed to parse /proc/{pid}/maps: {reason}")]
    MapsParseError { pid: i32, reason: String },

    // === Injection ===
    #[error("remote mmap failed, returned 0x{addr:x}")]
    MmapFailed { addr: u64 },

    #[error("dlopen failed for '{path}'")]
    DlopenFailed { path: PathBuf },

    #[error("dlsym failed for '{symbol}'")]
    DlsymFailed { symbol: String },

    // === Input validation ===
    #[error("invalid library path: {0}")]
    InvalidPath(PathBuf),

    #[error("path too long: max {max} bytes, got {actual}")]
    PathTooLong { max: usize, actual: usize },

    #[error("entry point name too long: max {max} bytes")]
    EntryPointTooLong { max: usize },

    #[error("argument too long: max {max} bytes")]
    ArgumentTooLong { max: usize },

    // === Permission ===
    #[error("permission denied: cannot ptrace process {pid} (try running as root)")]
    PermissionDenied { pid: i32 },

    // === IO ===
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convert ptrace attach error to appropriate Error variant
    pub fn from_attach(pid: i32, errno: Errno) -> Self {
        match errno {
            Errno::EPERM => Error::PermissionDenied { pid },
            Errno::ESRCH => Error::ProcessNotFound { pid },
            _ => Error::AttachFailed { pid, source: errno },
        }
    }
}
```

**Step 2: Update hsinject-backend/src/lib.rs**

```rust
//! hsinject-backend - Platform-specific injection implementation

pub mod error;
pub mod arch;

#[cfg(target_os = "linux")]
pub mod linux;
```

**Step 3: Verify it compiles**

Run: `cargo build -p hsinject-backend`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(backend): add error types"
```

---

## Task 3: Architecture Abstraction - x86_64

**Files:**
- Create: `hsinject-backend/src/arch/mod.rs`
- Create: `hsinject-backend/src/arch/x86_64.rs`

**Step 1: Create arch/mod.rs**

```rust
//! Architecture-specific code
//!
//! Uses cfg conditional compilation (Frida style) to select
//! the appropriate implementation at compile time.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

// Ensure we have an implementation for the current architecture
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture");
```

**Step 2: Create arch/x86_64.rs**

```rust
//! x86_64 architecture support

use libc::user_regs_struct;

/// Register type for this architecture
pub type Regs = user_regs_struct;

/// Get instruction pointer
#[inline]
pub fn get_ip(regs: &Regs) -> u64 {
    regs.rip
}

/// Set instruction pointer
#[inline]
pub fn set_ip(regs: &mut Regs, addr: u64) {
    regs.rip = addr;
}

/// Get stack pointer
#[inline]
pub fn get_sp(regs: &Regs) -> u64 {
    regs.rsp
}

/// Set stack pointer
#[inline]
pub fn set_sp(regs: &mut Regs, addr: u64) {
    regs.rsp = addr;
}

/// Get syscall return value
#[inline]
pub fn get_syscall_result(regs: &Regs) -> u64 {
    regs.rax
}

/// Get function return value (same as syscall result on x86_64)
#[inline]
pub fn get_return_value(regs: &Regs) -> u64 {
    regs.rax
}

/// Set syscall number and arguments
///
/// x86_64 syscall ABI:
/// - rax: syscall number
/// - rdi, rsi, rdx, r10, r8, r9: arguments 1-6
pub fn set_syscall_args(regs: &mut Regs, num: u64, args: &[u64]) {
    regs.rax = num;
    if args.len() > 0 { regs.rdi = args[0]; }
    if args.len() > 1 { regs.rsi = args[1]; }
    if args.len() > 2 { regs.rdx = args[2]; }
    if args.len() > 3 { regs.r10 = args[3]; }
    if args.len() > 4 { regs.r8 = args[4]; }
    if args.len() > 5 { regs.r9 = args[5]; }
}

/// syscall instruction bytes
pub const SYSCALL_INSN: &[u8] = &[0x0f, 0x05];

/// int3 (breakpoint) instruction
pub const TRAP_INSN: &[u8] = &[0xcc];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_set_ip() {
        let mut regs: Regs = unsafe { std::mem::zeroed() };
        set_ip(&mut regs, 0xdeadbeef);
        assert_eq!(get_ip(&regs), 0xdeadbeef);
    }

    #[test]
    fn test_get_set_sp() {
        let mut regs: Regs = unsafe { std::mem::zeroed() };
        set_sp(&mut regs, 0x7fff0000);
        assert_eq!(get_sp(&regs), 0x7fff0000);
    }

    #[test]
    fn test_syscall_args() {
        let mut regs: Regs = unsafe { std::mem::zeroed() };
        // SYS_mmap args: addr=0, len=4096, prot=3, flags=34, fd=-1, offset=0
        set_syscall_args(&mut regs, 9, &[0, 4096, 3, 34, u64::MAX, 0]);

        assert_eq!(regs.rax, 9);        // SYS_mmap
        assert_eq!(regs.rdi, 0);        // addr
        assert_eq!(regs.rsi, 4096);     // len
        assert_eq!(regs.rdx, 3);        // prot (PROT_READ | PROT_WRITE)
        assert_eq!(regs.r10, 34);       // flags (MAP_PRIVATE | MAP_ANONYMOUS)
        assert_eq!(regs.r8, u64::MAX);  // fd (-1)
        assert_eq!(regs.r9, 0);         // offset
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p hsinject-backend arch`
Expected: All tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(backend): add x86_64 architecture support"
```

---

## Task 4: Linux Module Structure

**Files:**
- Create: `hsinject-backend/src/linux/mod.rs`

**Step 1: Create linux/mod.rs**

```rust
//! Linux-specific injection implementation

pub mod ptrace;
pub mod process;
pub mod inject;
pub mod bootstrapper;
```

**Step 2: Create stub files**

Create `hsinject-backend/src/linux/ptrace.rs`:
```rust
//! Ptrace operations wrapper
```

Create `hsinject-backend/src/linux/process.rs`:
```rust
//! Process memory and maps parsing
```

Create `hsinject-backend/src/linux/inject.rs`:
```rust
//! High-level injection logic
```

Create `hsinject-backend/src/linux/bootstrapper.rs`:
```rust
//! Bootstrapper shellcode generation
```

**Step 3: Verify it compiles**

Run: `cargo build -p hsinject-backend`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(backend): add linux module structure"
```

---

## Task 5: Ptrace Wrapper

**Files:**
- Modify: `hsinject-backend/src/linux/ptrace.rs`

**Step 1: Implement TracedProcess**

```rust
//! Ptrace operations wrapper

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::arch::{self, Regs};
use crate::error::{Error, Result};

/// A process attached via ptrace
pub struct TracedProcess {
    pid: Pid,
    saved_regs: Regs,
    attached: bool,
}

impl TracedProcess {
    /// Attach to a running process
    pub fn attach(pid: Pid) -> Result<Self> {
        ptrace::attach(pid).map_err(|e| Error::from_attach(pid.as_raw(), e))?;
        Self::wait_for_stop(pid)?;

        let saved_regs = ptrace::getregs(pid).map_err(Error::RegAccessFailed)?;

        Ok(Self {
            pid,
            saved_regs,
            attached: true,
        })
    }

    /// Get the process ID
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Get current registers
    pub fn getregs(&self) -> Result<Regs> {
        ptrace::getregs(self.pid).map_err(Error::RegAccessFailed)
    }

    /// Set registers
    pub fn setregs(&self, regs: Regs) -> Result<()> {
        ptrace::setregs(self.pid, regs).map_err(Error::RegAccessFailed)
    }

    /// Wait for process to stop
    fn wait_for_stop(pid: Pid) -> Result<WaitStatus> {
        loop {
            match waitpid(pid, None) {
                Ok(status @ WaitStatus::Stopped(_, _)) => return Ok(status),
                Ok(WaitStatus::Exited(_, code)) => {
                    return Err(Error::ProcessTerminated {
                        pid: pid.as_raw(),
                        signal: code,
                    });
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    return Err(Error::ProcessTerminated {
                        pid: pid.as_raw(),
                        signal: sig as i32,
                    });
                }
                Ok(_) => continue,
                Err(e) => {
                    return Err(Error::AttachFailed {
                        pid: pid.as_raw(),
                        source: e,
                    });
                }
            }
        }
    }

    /// Wait for SIGTRAP (breakpoint)
    fn wait_for_trap(&self) -> Result<()> {
        match Self::wait_for_stop(self.pid)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => Ok(()),
            WaitStatus::Stopped(_, sig) => Err(Error::UnexpectedSignal { signal: sig as i32 }),
            _ => Err(Error::UnexpectedSignal { signal: 0 }),
        }
    }

    /// Read memory from the target process
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        let mut offset = 0usize;

        while offset < len {
            let word = ptrace::read(self.pid, (addr + offset as u64) as *mut _)
                .map_err(|e| Error::MemReadFailed { addr: addr + offset as u64, source: e })?;

            let bytes = word.to_ne_bytes();
            let remaining = len - offset;
            let to_copy = remaining.min(std::mem::size_of::<i64>());
            data.extend_from_slice(&bytes[..to_copy]);
            offset += std::mem::size_of::<i64>();
        }

        Ok(data)
    }

    /// Write memory to the target process
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<()> {
        let word_size = std::mem::size_of::<i64>();

        for (i, chunk) in data.chunks(word_size).enumerate() {
            let chunk_addr = addr + (i * word_size) as u64;

            let word = if chunk.len() < word_size {
                // Partial write: read existing word first
                let existing = ptrace::read(self.pid, chunk_addr as *mut _)
                    .map_err(|e| Error::MemReadFailed { addr: chunk_addr, source: e })?;
                let mut bytes = existing.to_ne_bytes();
                bytes[..chunk.len()].copy_from_slice(chunk);
                i64::from_ne_bytes(bytes)
            } else {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                i64::from_ne_bytes(bytes)
            };

            // SAFETY: We're writing to the target process memory
            unsafe {
                ptrace::write(self.pid, chunk_addr as *mut _, word as *mut _)
                    .map_err(|e| Error::MemWriteFailed { addr: chunk_addr, source: e })?;
            }
        }

        Ok(())
    }

    /// Execute code at the given address until a breakpoint is hit
    pub fn execute_until_trap(&self, code_addr: u64) -> Result<Regs> {
        let mut regs = self.getregs()?;
        arch::set_ip(&mut regs, code_addr);
        self.setregs(regs)?;

        ptrace::cont(self.pid, None).map_err(|e| Error::AttachFailed {
            pid: self.pid.as_raw(),
            source: e,
        })?;

        self.wait_for_trap()?;
        self.getregs()
    }

    /// Restore original state and detach
    pub fn detach(mut self) -> Result<()> {
        self.do_detach()
    }

    fn do_detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }

        ptrace::setregs(self.pid, self.saved_regs).map_err(Error::RegAccessFailed)?;
        ptrace::detach(self.pid, None).map_err(|e| Error::DetachFailed {
            pid: self.pid.as_raw(),
            source: e,
        })?;

        self.attached = false;
        Ok(())
    }
}

impl Drop for TracedProcess {
    fn drop(&mut self) {
        if self.attached {
            // Best effort cleanup
            let _ = ptrace::setregs(self.pid, self.saved_regs);
            let _ = ptrace::detach(self.pid, None);
        }
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p hsinject-backend`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(backend): implement TracedProcess ptrace wrapper"
```

---

## Task 6: Process Maps Parsing

**Files:**
- Modify: `hsinject-backend/src/linux/process.rs`

**Step 1: Implement maps parsing**

```rust
//! Process memory and maps parsing

use std::fs;
use std::path::Path;

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
}
```

**Step 2: Run tests**

Run: `cargo test -p hsinject-backend process`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(backend): implement process maps parsing"
```

---

## Task 7: Symbol Resolution

**Files:**
- Modify: `hsinject-backend/src/linux/process.rs`

**Step 1: Add symbol resolution functions**

Add to `hsinject-backend/src/linux/process.rs`:

```rust
use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;

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
    // ... existing tests ...

    #[test]
    fn test_get_local_libc_path() {
        let path = super::get_local_libc_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.contains("libc"));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p hsinject-backend process`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(backend): add symbol resolution"
```

---

## Task 8: Bootstrapper Shellcode

**Files:**
- Modify: `hsinject-backend/src/linux/bootstrapper.rs`
- Modify: `hsinject-backend/src/arch/x86_64.rs`

**Step 1: Define BootstrapParams**

In `hsinject-backend/src/linux/bootstrapper.rs`:

```rust
//! Bootstrapper shellcode generation

/// Parameters passed to the bootstrapper shellcode
///
/// Memory layout:
/// - [0..64]      BootstrapParams struct
/// - [64..256]    Bootstrapper shellcode
/// - [256..512]   Library path string
/// - [512..768]   Entry point name string
/// - [768..1024]  Argument string
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootstrapParams {
    /// Address of __libc_dlopen_mode function
    pub dlopen_addr: u64,
    /// Address of dlsym function
    pub dlsym_addr: u64,
    /// Address of library path string
    pub lib_path_addr: u64,
    /// dlopen flags (RTLD_NOW = 2)
    pub dlopen_flags: u64,
    /// Address of entry point function name (0 if none)
    pub entry_point_addr: u64,
    /// Address of argument string (0 if none)
    pub argument_addr: u64,
    /// Output: dlopen handle
    pub result_handle: u64,
    /// Output: entry point return value
    pub result_retval: u64,
}

impl BootstrapParams {
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Convert to bytes for writing to remote memory
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                Self::SIZE,
            )
        }
    }

    /// Read from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(unsafe { std::ptr::read(bytes.as_ptr() as *const Self) })
    }
}

/// Memory layout offsets
pub mod layout {
    pub const PARAMS_OFFSET: u64 = 0;
    pub const CODE_OFFSET: u64 = 64;
    pub const LIB_PATH_OFFSET: u64 = 256;
    pub const ENTRY_POINT_OFFSET: u64 = 512;
    pub const ARGUMENT_OFFSET: u64 = 768;
    pub const TOTAL_SIZE: u64 = 1024;

    pub const MAX_PATH_LEN: usize = 256;
    pub const MAX_ENTRY_POINT_LEN: usize = 256;
    pub const MAX_ARGUMENT_LEN: usize = 256;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_size() {
        assert_eq!(BootstrapParams::SIZE, 64);
    }

    #[test]
    fn test_params_roundtrip() {
        let params = BootstrapParams {
            dlopen_addr: 0x7f0000001000,
            dlsym_addr: 0x7f0000002000,
            lib_path_addr: 0x7f0000003000,
            dlopen_flags: 2,
            entry_point_addr: 0x7f0000004000,
            argument_addr: 0x7f0000005000,
            result_handle: 0,
            result_retval: 0,
        };

        let bytes = params.as_bytes();
        let restored = BootstrapParams::from_bytes(bytes).unwrap();

        assert_eq!(restored.dlopen_addr, params.dlopen_addr);
        assert_eq!(restored.dlsym_addr, params.dlsym_addr);
        assert_eq!(restored.entry_point_addr, params.entry_point_addr);
    }
}
```

**Step 2: Add shellcode generation to x86_64.rs**

Add to `hsinject-backend/src/arch/x86_64.rs`:

```rust
use crate::linux::bootstrapper::BootstrapParams;

/// Generate bootstrapper shellcode for x86_64
///
/// The shellcode:
/// 1. Calls dlopen(lib_path, flags) -> handle
/// 2. Stores handle to params.result_handle
/// 3. If entry_point_addr != 0: calls dlsym(handle, entry_point) -> func
/// 4. If func != 0: calls func(argument) -> retval
/// 5. Stores retval to params.result_retval
/// 6. Executes int3 to return control
pub fn bootstrapper_shellcode(params_addr: u64) -> Vec<u8> {
    let mut code = Vec::new();

    // Save params address in r12 (callee-saved)
    // movabs r12, params_addr
    code.extend_from_slice(&[0x49, 0xbc]);
    code.extend_from_slice(&params_addr.to_le_bytes());

    // === 1. dlopen(lib_path, flags) ===
    // mov rdi, [r12 + 16]  ; lib_path_addr
    code.extend_from_slice(&[0x49, 0x8b, 0x7c, 0x24, 16]);
    // mov rsi, [r12 + 24]  ; dlopen_flags
    code.extend_from_slice(&[0x49, 0x8b, 0x74, 0x24, 24]);
    // mov rax, [r12 + 0]   ; dlopen_addr
    code.extend_from_slice(&[0x49, 0x8b, 0x44, 0x24, 0]);
    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);
    // mov [r12 + 48], rax  ; result_handle
    code.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, 48]);

    // === 2. Check if entry_point_addr != 0 ===
    // mov rcx, [r12 + 32]  ; entry_point_addr
    code.extend_from_slice(&[0x49, 0x8b, 0x4c, 0x24, 32]);
    // test rcx, rcx
    code.extend_from_slice(&[0x48, 0x85, 0xc9]);
    // jz done
    let jz1_pos = code.len();
    code.extend_from_slice(&[0x74, 0x00]); // placeholder

    // === 3. dlsym(handle, entry_point) ===
    // mov rdi, rax         ; handle
    code.extend_from_slice(&[0x48, 0x89, 0xc7]);
    // mov rsi, rcx         ; entry_point
    code.extend_from_slice(&[0x48, 0x89, 0xce]);
    // mov rax, [r12 + 8]   ; dlsym_addr
    code.extend_from_slice(&[0x49, 0x8b, 0x44, 0x24, 8]);
    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);

    // === 4. Check if func != 0 ===
    // test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jz done
    let jz2_pos = code.len();
    code.extend_from_slice(&[0x74, 0x00]); // placeholder

    // === 5. func(argument) ===
    // mov rdi, [r12 + 40]  ; argument_addr
    code.extend_from_slice(&[0x49, 0x8b, 0x7c, 0x24, 40]);
    // call rax
    code.extend_from_slice(&[0xff, 0xd0]);
    // mov [r12 + 56], rax  ; result_retval
    code.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, 56]);

    // done:
    let done_pos = code.len();

    // Patch jump offsets
    code[jz1_pos + 1] = (done_pos - jz1_pos - 2) as u8;
    code[jz2_pos + 1] = (done_pos - jz2_pos - 2) as u8;

    // === 6. int3 ===
    code.push(0xcc);

    code
}

#[cfg(test)]
mod tests {
    use super::*;

    // ... existing tests ...

    #[test]
    fn test_bootstrapper_shellcode() {
        let shellcode = bootstrapper_shellcode(0x7fff0000);
        assert!(!shellcode.is_empty());
        // Last byte should be int3
        assert_eq!(shellcode.last(), Some(&0xcc));
        // Should contain movabs r12 (0x49 0xbc)
        assert!(shellcode.windows(2).any(|w| w == [0x49, 0xbc]));
    }
}
```

**Step 3: Update imports**

In `hsinject-backend/src/arch/x86_64.rs`, add at the top:
```rust
#[cfg(target_os = "linux")]
use crate::linux::bootstrapper::BootstrapParams;
```

**Step 4: Run tests**

Run: `cargo test -p hsinject-backend`
Expected: All tests pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(backend): implement bootstrapper shellcode for x86_64"
```

---

## Task 9: Injection Logic

**Files:**
- Modify: `hsinject-backend/src/linux/inject.rs`

**Step 1: Implement injection**

```rust
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
    let entry_point_addr = remote_mem + layout::ENTRY_POINT_OFFSET;
    let argument_addr = remote_mem + layout::ARGUMENT_OFFSET;

    // Write library path
    write_string(&proc, lib_path_addr, lib_path_str)?;

    // Write entry point if provided
    let entry_point_addr = if let Some(ep) = entry_point {
        write_string(&proc, entry_point_addr, ep)?;
        entry_point_addr
    } else {
        0
    };

    // Write argument if provided
    let argument_addr = if let Some(arg) = argument {
        write_string(&proc, argument_addr, arg)?;
        argument_addr
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
```

**Step 2: Verify it compiles**

Run: `cargo build -p hsinject-backend`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(backend): implement injection logic"
```

---

## Task 10: High-Level API

**Files:**
- Modify: `hsinject/src/lib.rs`

**Step 1: Implement public API**

```rust
//! hsinject - Linux process injection library
//!
//! # Example
//!
//! ```no_run
//! use hsinject::{inject, Payload, InjectOptions};
//!
//! let result = inject(
//!     1234,
//!     Payload::Library("/path/to/lib.so".into()),
//!     InjectOptions {
//!         entry_point: Some("my_init".into()),
//!         argument: Some("config=debug".into()),
//!     },
//! ).unwrap();
//!
//! println!("Injected! handle=0x{:x}", result.handle);
//! ```

pub use hsinject_backend::error::{Error, Result};

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use hsinject_backend::linux::inject::{inject_library, inject_shellcode};

/// Injection payload
pub enum Payload {
    /// Shared library (.so) path
    Library(PathBuf),
    /// Raw shellcode bytes
    Shellcode(Vec<u8>),
}

/// Injection options
#[derive(Default, Clone)]
pub struct InjectOptions {
    /// Entry point function name (for library injection)
    ///
    /// If specified, after loading the library, this function will be called
    /// with the `argument` as its parameter.
    pub entry_point: Option<String>,

    /// Argument to pass to entry point function
    ///
    /// Passed as a C string pointer to the entry point function.
    pub argument: Option<String>,
}

/// Injection result
#[derive(Debug)]
pub struct InjectResult {
    /// Target process ID
    pub pid: i32,
    /// dlopen handle (for library injection, 0 for shellcode)
    pub handle: u64,
    /// Entry point return value (or shellcode return value)
    pub retval: u64,
}

/// Inject payload into a running process
///
/// # Arguments
///
/// * `pid` - Target process ID
/// * `payload` - What to inject (library or shellcode)
/// * `options` - Injection options (entry point, argument)
///
/// # Returns
///
/// `InjectResult` containing the dlopen handle and entry point return value
///
/// # Errors
///
/// Returns an error if:
/// - Cannot attach to the process (permission denied, process not found)
/// - Cannot allocate memory in the target process
/// - dlopen fails to load the library
/// - dlsym fails to find the entry point
///
/// # Example
///
/// ```no_run
/// use hsinject::{inject, Payload, InjectOptions};
///
/// // Simple library injection
/// let result = inject(
///     1234,
///     Payload::Library("/tmp/hook.so".into()),
///     InjectOptions::default(),
/// )?;
/// # Ok::<(), hsinject::Error>(())
/// ```
#[cfg(target_os = "linux")]
pub fn inject(pid: i32, payload: Payload, options: InjectOptions) -> Result<InjectResult> {
    match payload {
        Payload::Library(path) => {
            let result = inject_library(
                pid,
                &path,
                options.entry_point.as_deref(),
                options.argument.as_deref(),
            )?;
            Ok(InjectResult {
                pid: result.pid,
                handle: result.handle,
                retval: result.retval,
            })
        }
        Payload::Shellcode(code) => {
            let result = inject_shellcode(pid, &code)?;
            Ok(InjectResult {
                pid: result.pid,
                handle: result.handle,
                retval: result.retval,
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn inject(_pid: i32, _payload: Payload, _options: InjectOptions) -> Result<InjectResult> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "injection is only supported on Linux",
    )))
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p hsinject`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: implement high-level injection API"
```

---

## Task 11: CLI Tool

**Files:**
- Modify: `hsinject-cli/src/main.rs`

**Step 1: Implement CLI**

```rust
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

use hsinject::{inject, InjectOptions, Payload};

#[derive(Parser)]
#[command(name = "hsinject")]
#[command(about = "Inject shared libraries or shellcode into running processes")]
#[command(version)]
struct Cli {
    /// Target process ID
    #[arg(short, long)]
    pid: i32,

    /// Path to shared library (.so) to inject
    #[arg(short, long, group = "payload")]
    library: Option<PathBuf>,

    /// Path to raw shellcode file to inject
    #[arg(short, long, group = "payload")]
    shellcode: Option<PathBuf>,

    /// Entry point function name (for library injection)
    #[arg(short, long)]
    entry: Option<String>,

    /// Argument to pass to entry point function
    #[arg(short, long)]
    arg: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let payload = match (&cli.library, &cli.shellcode) {
        (Some(lib), None) => {
            if cli.verbose {
                eprintln!("[*] Loading library: {}", lib.display());
            }
            Payload::Library(lib.clone())
        }
        (None, Some(sc)) => {
            let data = std::fs::read(sc)
                .with_context(|| format!("failed to read shellcode file: {}", sc.display()))?;
            if cli.verbose {
                eprintln!("[*] Loading shellcode: {} ({} bytes)", sc.display(), data.len());
            }
            Payload::Shellcode(data)
        }
        (Some(_), Some(_)) => {
            bail!("cannot specify both --library and --shellcode");
        }
        (None, None) => {
            bail!("must specify either --library or --shellcode");
        }
    };

    let options = InjectOptions {
        entry_point: cli.entry.clone(),
        argument: cli.arg.clone(),
    };

    if cli.verbose {
        eprintln!("[*] Target PID: {}", cli.pid);
        if let Some(ref ep) = options.entry_point {
            eprintln!("[*] Entry point: {}", ep);
        }
        if let Some(ref arg) = options.argument {
            eprintln!("[*] Argument: {}", arg);
        }
        eprintln!("[*] Attaching to process...");
    }

    let result = inject(cli.pid, payload, options)
        .with_context(|| format!("failed to inject into process {}", cli.pid))?;

    if cli.verbose {
        eprintln!("[+] Injection successful!");
        eprintln!("    PID: {}", result.pid);
        if result.handle != 0 {
            eprintln!("    Handle: 0x{:x}", result.handle);
        }
        if result.retval != 0 {
            eprintln!("    Return value: 0x{:x}", result.retval);
        }
    } else {
        println!("0x{:x}", result.handle);
    }

    Ok(())
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p hsinject-cli`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(cli): implement command-line interface"
```

---

## Task 12: Integration Test Library

**Files:**
- Create: `tests/test_lib/Cargo.toml`
- Create: `tests/test_lib/src/lib.rs`

**Step 1: Create test library Cargo.toml**

```toml
[package]
name = "test_lib"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
libc = "0.2"
```

**Step 2: Create test library source**

```rust
//! Test library for hsinject integration tests

use std::fs;
use std::ffi::CStr;

/// Marker file to verify injection
const MARKER_FILE: &str = "/tmp/hsinject_test_marker";

/// Constructor - called when library is loaded via dlopen
#[no_mangle]
#[ctor::ctor]
fn constructor() {
    let _ = fs::write(MARKER_FILE, "constructor_called");
}

/// Entry point function for testing
#[no_mangle]
pub extern "C" fn test_entry(arg: *const libc::c_char) -> libc::c_int {
    let arg_str = if arg.is_null() {
        "null".to_string()
    } else {
        unsafe { CStr::from_ptr(arg).to_string_lossy().into_owned() }
    };

    let content = format!("entry_called:{}", arg_str);
    let _ = fs::write(MARKER_FILE, content);

    42 // return value
}
```

**Step 3: Add ctor dependency**

Update `tests/test_lib/Cargo.toml`:
```toml
[package]
name = "test_lib"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
libc = "0.2"
ctor = "0.2"
```

**Step 4: Add test lib to workspace**

Update root `Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "hsinject",
    "hsinject-backend",
    "hsinject-cli",
    "tests/test_lib",
]
```

**Step 5: Build test library**

Run: `cargo build -p test_lib`
Expected: Build succeeds, produces `target/debug/libtest_lib.so`

**Step 6: Commit**

```bash
git add -A
git commit -m "test: add integration test library"
```

---

## Task 13: Integration Tests

**Files:**
- Create: `hsinject/tests/integration.rs`

**Step 1: Create integration tests**

```rust
//! Integration tests for hsinject
//!
//! These tests require:
//! 1. Root privileges (for ptrace)
//! 2. Built test library (cargo build -p test_lib)

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use hsinject::{inject, InjectOptions, Payload};

const MARKER_FILE: &str = "/tmp/hsinject_test_marker";

fn cleanup_marker() {
    let _ = fs::remove_file(MARKER_FILE);
}

fn read_marker() -> Option<String> {
    fs::read_to_string(MARKER_FILE).ok()
}

fn spawn_target() -> std::process::Child {
    Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn target process")
}

fn get_test_lib_path() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("target/debug/libtest_lib.so")
}

#[test]
#[ignore] // requires root
fn test_inject_library_constructor() {
    cleanup_marker();

    let mut child = spawn_target();
    let pid = child.id() as i32;

    let lib_path = get_test_lib_path();
    if !lib_path.exists() {
        eprintln!("Test library not found at {:?}, skipping", lib_path);
        child.kill().ok();
        return;
    }

    let result = inject(pid, Payload::Library(lib_path), InjectOptions::default());

    // Give constructor time to run
    thread::sleep(Duration::from_millis(100));

    child.kill().ok();

    assert!(result.is_ok(), "injection failed: {:?}", result.err());
    let result = result.unwrap();
    assert_ne!(result.handle, 0, "dlopen returned null handle");

    let marker = read_marker();
    assert_eq!(marker, Some("constructor_called".to_string()));

    cleanup_marker();
}

#[test]
#[ignore] // requires root
fn test_inject_library_with_entry_point() {
    cleanup_marker();

    let mut child = spawn_target();
    let pid = child.id() as i32;

    let lib_path = get_test_lib_path();
    if !lib_path.exists() {
        eprintln!("Test library not found at {:?}, skipping", lib_path);
        child.kill().ok();
        return;
    }

    let result = inject(
        pid,
        Payload::Library(lib_path),
        InjectOptions {
            entry_point: Some("test_entry".to_string()),
            argument: Some("hello".to_string()),
        },
    );

    thread::sleep(Duration::from_millis(100));

    child.kill().ok();

    assert!(result.is_ok(), "injection failed: {:?}", result.err());
    let result = result.unwrap();
    assert_ne!(result.handle, 0);
    assert_eq!(result.retval, 42);

    let marker = read_marker();
    assert_eq!(marker, Some("entry_called:hello".to_string()));

    cleanup_marker();
}

#[test]
#[ignore] // requires root
fn test_inject_nonexistent_process() {
    let result = inject(
        999999,
        Payload::Library("/tmp/test.so".into()),
        InjectOptions::default(),
    );

    assert!(result.is_err());
}
```

**Step 2: Run tests (as root)**

Run: `sudo cargo test -p hsinject --test integration -- --ignored`
Expected: Tests pass (if running as root with test lib built)

**Step 3: Commit**

```bash
git add -A
git commit -m "test: add integration tests"
```

---

## Task 14: Final Cleanup and Documentation

**Files:**
- Modify: `README.md` (create)
- Verify all builds

**Step 1: Create README.md**

```markdown
# hsinject

A Rust library for Linux process injection, inspired by Frida's injection mechanism.

## Features

- **Library injection**: Inject shared libraries (.so) into running processes
- **Shellcode injection**: Inject raw shellcode
- **Entry point support**: Call a specific function after injection
- **x86_64 support**: Currently supports x86_64 architecture

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hsinject = { git = "https://github.com/user/hsinject" }
```

## Usage

### As a library

```rust
use hsinject::{inject, Payload, InjectOptions};

// Simple library injection
let result = inject(
    1234,
    Payload::Library("/path/to/hook.so".into()),
    InjectOptions::default(),
)?;

// With entry point
let result = inject(
    1234,
    Payload::Library("/path/to/hook.so".into()),
    InjectOptions {
        entry_point: Some("my_init".into()),
        argument: Some("config=debug".into()),
    },
)?;

println!("Injected! handle=0x{:x}", result.handle);
```

### As a CLI tool

```bash
# Inject a shared library
sudo hsinject -p 1234 -l ./libhook.so

# With entry point and argument
sudo hsinject -p 1234 -l ./libhook.so -e my_init -a "config=debug"

# Inject shellcode
sudo hsinject -p 1234 -s ./payload.bin

# Verbose output
sudo hsinject -p 1234 -l ./libhook.so -v
```

## Building

```bash
# Build all
cargo build --release

# Build with musl
cargo build --release --target x86_64-unknown-linux-musl

# Run tests (requires root)
sudo cargo test -- --ignored
```

## Architecture Support

- [x] x86_64
- [ ] aarch64
- [ ] arm
- [ ] x86

## License

MIT
```

**Step 2: Verify full build**

Run: `cargo build --release`
Expected: Build succeeds

**Step 3: Verify tests**

Run: `cargo test`
Expected: Unit tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "docs: add README"
```

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Workspace setup |
| 2 | Error types |
| 3 | x86_64 architecture support |
| 4 | Linux module structure |
| 5 | Ptrace wrapper |
| 6 | Process maps parsing |
| 7 | Symbol resolution |
| 8 | Bootstrapper shellcode |
| 9 | Injection logic |
| 10 | High-level API |
| 11 | CLI tool |
| 12 | Integration test library |
| 13 | Integration tests |
| 14 | Documentation |
