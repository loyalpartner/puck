//! Minimal Linux process injection library inspired by Frida
//!
//! This library implements Frida-style two-stage injection:
//! 1. Bootstrapper resolves libc symbols from inside target process
//! 2. New thread performs dlopen + dlsym + function call
//!
//! Benefits:
//! - dlopen happens in clean thread context (no TLS/signal issues)
//! - Single dlopen reference (library can properly unload via dlclose)
//! - Reliable symbol resolution using target's own linker structures

pub mod bootstrap;
mod error;
mod elf;
mod ptrace;
mod call;
mod inject;
mod libc_resolver;
mod code_swap;

pub use error::{Error, Result};
pub use bootstrap::{BootstrapStatus, BootstrapMode, LibcApi};
pub use inject::{
    inject_library,
    inject_and_call,
    inject_and_call_with_string,
    call_in_loaded_library,
    InjectionResult,
    InjectionCallResult,
};
