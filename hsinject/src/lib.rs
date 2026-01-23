//! Minimal Linux process injection library inspired by Frida
//!
//! This is a simplified implementation that:
//! 1. Parses ELF to find symbol offsets (like Frida's Gum)
//! 2. Uses ptrace to control the target process
//! 3. Injects shellcode that calls dlopen/dlsym

mod error;
mod elf;
mod ptrace;
mod call;
mod inject;

pub use error::{Error, Result};
pub use inject::{
    inject_library,
    inject_and_call,
    inject_and_call_with_string,
    InjectionResult,
    InjectionCallResult,
};
