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
}
