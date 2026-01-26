# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Puck is a Rust library for Linux process injection, implementing Frida's two-stage injection mechanism. It injects shared libraries (.so) into running processes and calls functions within them. Supports x86_64 and aarch64 architectures.

## Build Commands

```bash
# Build for host architecture
make build                    # cargo build --release + bootstrapper

# Build for aarch64
make build-aarch64            # cross-compile for aarch64

# Run QEMU integration tests
make test-x86_64              # builds labrats/payloads, runs pytest
make test-aarch64             # same for aarch64

# Run local integration tests (requires sudo)
make test                     # builds + sudo uv run pytest tests/integration

# Setup QEMU VM images (one-time)
make setup
```

### Running Individual Tests

```bash
# Single QEMU test
uv run pytest tests/qemu/test_qemu_injection.py::test_inject_library -v --arch x86_64

# Single integration test (requires sudo)
sudo uv run pytest tests/integration/test_injection.py::test_name -v
```

## Architecture

### Two-Stage Injection Flow

```
Injector (Rust)                    Target Process
    │                                    │
    ├─ ptrace attach ───────────────────►│
    ├─ mmap memory ─────────────────────►│
    ├─ write bootstrapper + context ────►│
    ├─ execute bootstrapper ────────────►│
    │                                    ├─ Stage 1: Parse auxv, find r_debug
    │                                    ├─ Traverse link_map to find libc
    │                                    ├─ Resolve dlopen/pthread_create
    │                                    ├─ Stage 2: Create loader thread
    │                                    │    ├─ dlopen(library)
    │                                    │    ├─ dlsym(function)
    │                                    │    └─ call function
    │◄─ read status from context ────────┤
    └─ ptrace detach ───────────────────►│
```

### Key Components

| Location | Purpose |
|----------|---------|
| `puck/src/inject.rs` | Main injection orchestration |
| `puck/src/bootstrap/` | Executes shellcode, manages context structs |
| `puck/src/call.rs` | Remote syscalls (mmap), register setup by arch |
| `puck/src/ptrace.rs` | ptrace wrapper, multi-thread handling |
| `puck/src/libc_resolver.rs` | Resolve libc offsets locally, apply to remote |
| `puck/src/code_swap.rs` | Temporary executable memory borrowing |
| `bootstrapper/` | Position-independent C shellcode (both archs) |

### Memory Layout in Target Process

The bootstrapper allocates ~10KB: bootstrapper code (4KB RX), context struct (224 bytes), strings (library path, function name, argument), and stack for the loader thread (4KB).

### Bootstrap Context (224 bytes)

Defined in both `puck/src/bootstrap/context.rs` (Rust) and `bootstrapper/bootstrapper.h` (C). These must stay in sync. The context carries:
- Input: mode (LOAD/CALL), library path, function name, argument pointers
- Output: status code, dlopen handle, resolved libc API pointers

## Testing

- pytest managed by uv
- QEMU tests use session-scoped VMs (reused across tests for speed)
- Test payloads in `tests/qemu/payloads/libhello.c`
- Test target processes ("labrats") in `tests/qemu/labrats/`

## Injection Modes

**LOAD mode**: Inject new library, call function
```bash
sudo puck -l ./libhook.so -f entry <pid>
```

**CALL mode**: Call function in already-loaded library
```bash
sudo puck -c libc.so.6 -f puts -d "hello" <pid>
```
