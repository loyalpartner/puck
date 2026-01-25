//! Bootstrap context structures shared with C bootstrapper
//!
//! These structures must match the layout in bootstrapper.h exactly.

/// Bootstrap operation mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    /// Load library and call function (dlopen + dlsym + call)
    Load = 0,
    /// Call function in already-loaded library (find in link_map + call)
    Call = 1,
}

/// Status codes returned by the bootstrapper
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    /// Bootstrap completed successfully
    Success = 0,
    /// Failed to parse /proc/self/auxv
    AuxvParseFailed = 1,
    /// Could not find r_debug structure
    RDebugNotFound = 2,
    /// Could not find libc.so in link_map
    LibcNotFound = 3,
    /// Failed to resolve required libc symbols
    SymbolResolutionFailed = 4,
    /// dlopen failed
    DlopenFailed = 5,
    /// dlsym failed
    DlsymFailed = 6,
    /// pthread_create failed
    PthreadFailed = 7,
    /// Library not found in link_map (for CALL mode)
    LibraryNotLoaded = 8,
}

impl BootstrapStatus {
    /// Convert from raw u32 value
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::AuxvParseFailed),
            2 => Some(Self::RDebugNotFound),
            3 => Some(Self::LibcNotFound),
            4 => Some(Self::SymbolResolutionFailed),
            5 => Some(Self::DlopenFailed),
            6 => Some(Self::DlsymFailed),
            7 => Some(Self::PthreadFailed),
            8 => Some(Self::LibraryNotLoaded),
            _ => None,
        }
    }
}

/// Resolved libc API function addresses (for debugging)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LibcApi {
    pub dlopen: u64,
    pub dlclose: u64,
    pub dlsym: u64,
    pub dlerror: u64,
    pub pthread_create: u64,
    pub pthread_detach: u64,
}

/// Bootstrap context - passed to/from bootstrapper
///
/// Memory layout (224 bytes total):
/// - Input fields (set by injector)
/// - Output fields (set by bootstrapper)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootstrapContext {
    // === Input fields ===
    /// Operation mode: Load or Call
    pub mode: u32,
    /// Padding
    pub _pad0: u32,
    /// Pointer to library path (for Load) or pattern (for Call)
    pub library_path: u64,
    /// Pointer to function name
    pub function_name: u64,
    /// Pointer to argument data
    pub argument: u64,

    // === Output fields ===
    /// Result status
    pub status: u32,
    /// Padding
    pub _pad1: u32,
    /// Handle returned by dlopen
    pub handle: u64,
    /// Resolved libc APIs
    pub libc: LibcApi,
    /// Reserved
    pub _reserved: [u64; 16],
}

impl Default for BootstrapContext {
    fn default() -> Self {
        Self {
            mode: BootstrapMode::Load as u32,
            _pad0: 0,
            library_path: 0,
            function_name: 0,
            argument: 0,
            status: BootstrapStatus::AuxvParseFailed as u32,
            _pad1: 0,
            handle: 0,
            libc: LibcApi::default(),
            _reserved: [0; 16],
        }
    }
}

impl BootstrapContext {
    /// Create a new context for loading a library and calling a function
    pub fn new_load(library_path: u64, function_name: u64, argument: u64) -> Self {
        Self {
            mode: BootstrapMode::Load as u32,
            library_path,
            function_name,
            argument,
            ..Default::default()
        }
    }

    /// Create a new context for calling a function in an already-loaded library
    pub fn new_call(library_pattern: u64, function_name: u64, argument: u64) -> Self {
        Self {
            mode: BootstrapMode::Call as u32,
            library_path: library_pattern,
            function_name,
            argument,
            ..Default::default()
        }
    }

    /// Convert to raw bytes for writing to target memory
    pub fn to_bytes(&self) -> [u8; 224] {
        let mut bytes = [0u8; 224];
        let mut offset = 0;

        // Input fields
        bytes[offset..offset + 4].copy_from_slice(&self.mode.to_ne_bytes());
        offset += 4;
        bytes[offset..offset + 4].copy_from_slice(&self._pad0.to_ne_bytes());
        offset += 4;
        bytes[offset..offset + 8].copy_from_slice(&self.library_path.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.function_name.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.argument.to_ne_bytes());
        offset += 8;

        // Output fields
        bytes[offset..offset + 4].copy_from_slice(&self.status.to_ne_bytes());
        offset += 4;
        bytes[offset..offset + 4].copy_from_slice(&self._pad1.to_ne_bytes());
        offset += 4;
        bytes[offset..offset + 8].copy_from_slice(&self.handle.to_ne_bytes());
        offset += 8;

        // LibcApi
        bytes[offset..offset + 8].copy_from_slice(&self.libc.dlopen.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.libc.dlclose.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.libc.dlsym.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.libc.dlerror.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.libc.pthread_create.to_ne_bytes());
        offset += 8;
        bytes[offset..offset + 8].copy_from_slice(&self.libc.pthread_detach.to_ne_bytes());

        // Reserved bytes are already zero
        bytes
    }

    /// Parse from raw bytes read from target memory
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 224 {
            return None;
        }

        let mut offset = 0;

        let mode = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().ok()?);
        offset += 4;
        let _pad0 = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().ok()?);
        offset += 4;
        let library_path = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let function_name = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let argument = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let status = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().ok()?);
        offset += 4;
        let _pad1 = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().ok()?);
        offset += 4;
        let handle = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let libc = LibcApi {
            dlopen: u64::from_ne_bytes(bytes[offset..offset + 8].try_into().ok()?),
            dlclose: u64::from_ne_bytes(bytes[offset + 8..offset + 16].try_into().ok()?),
            dlsym: u64::from_ne_bytes(bytes[offset + 16..offset + 24].try_into().ok()?),
            dlerror: u64::from_ne_bytes(bytes[offset + 24..offset + 32].try_into().ok()?),
            pthread_create: u64::from_ne_bytes(bytes[offset + 32..offset + 40].try_into().ok()?),
            pthread_detach: u64::from_ne_bytes(bytes[offset + 40..offset + 48].try_into().ok()?),
        };

        Some(Self {
            mode,
            _pad0,
            library_path,
            function_name,
            argument,
            status,
            _pad1,
            handle,
            libc,
            _reserved: [0; 16],
        })
    }

    /// Get the status as an enum
    pub fn get_status(&self) -> Option<BootstrapStatus> {
        BootstrapStatus::from_u32(self.status)
    }
}

// Ensure the context has expected size for C interop
const _: () = {
    assert!(std::mem::size_of::<BootstrapContext>() == 224);
    assert!(std::mem::size_of::<LibcApi>() == 48);
};
