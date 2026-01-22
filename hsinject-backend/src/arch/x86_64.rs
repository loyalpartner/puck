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
    if args.len() > 0 {
        regs.rdi = args[0];
    }
    if args.len() > 1 {
        regs.rsi = args[1];
    }
    if args.len() > 2 {
        regs.rdx = args[2];
    }
    if args.len() > 3 {
        regs.r10 = args[3];
    }
    if args.len() > 4 {
        regs.r8 = args[4];
    }
    if args.len() > 5 {
        regs.r9 = args[5];
    }
}

/// syscall instruction bytes
pub const SYSCALL_INSN: &[u8] = &[0x0f, 0x05];

/// int3 (breakpoint) instruction
pub const TRAP_INSN: &[u8] = &[0xcc];

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

        assert_eq!(regs.rax, 9); // SYS_mmap
        assert_eq!(regs.rdi, 0); // addr
        assert_eq!(regs.rsi, 4096); // len
        assert_eq!(regs.rdx, 3); // prot (PROT_READ | PROT_WRITE)
        assert_eq!(regs.r10, 34); // flags (MAP_PRIVATE | MAP_ANONYMOUS)
        assert_eq!(regs.r8, u64::MAX); // fd (-1)
        assert_eq!(regs.r9, 0); // offset
    }

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
