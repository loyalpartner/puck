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
