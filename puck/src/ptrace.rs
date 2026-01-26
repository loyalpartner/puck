//! Ptrace wrapper for process control

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use libc::user_regs_struct;
use std::fs;

use crate::error::{Error, Result};

// Platform-specific register access
#[cfg(target_arch = "x86_64")]
fn ptrace_getregs(pid: Pid) -> nix::Result<user_regs_struct> {
    ptrace::getregs(pid)
}

#[cfg(target_arch = "x86_64")]
fn ptrace_setregs(pid: Pid, regs: user_regs_struct) -> nix::Result<()> {
    ptrace::setregs(pid, regs)
}

#[cfg(target_arch = "aarch64")]
fn ptrace_getregs(pid: Pid) -> nix::Result<user_regs_struct> {
    use std::mem::MaybeUninit;

    let mut regs = MaybeUninit::<user_regs_struct>::uninit();
    let mut iovec = libc::iovec {
        iov_base: regs.as_mut_ptr() as *mut libc::c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };

    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid.as_raw(),
            libc::NT_PRSTATUS,
            &mut iovec as *mut libc::iovec,
        )
    };

    if ret == -1 {
        Err(nix::errno::Errno::last())
    } else {
        Ok(unsafe { regs.assume_init() })
    }
}

#[cfg(target_arch = "aarch64")]
fn ptrace_setregs(pid: Pid, regs: user_regs_struct) -> nix::Result<()> {
    let mut iovec = libc::iovec {
        iov_base: &regs as *const user_regs_struct as *mut libc::c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };

    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid.as_raw(),
            libc::NT_PRSTATUS,
            &mut iovec as *mut libc::iovec,
        )
    };

    if ret == -1 {
        Err(nix::errno::Errno::last())
    } else {
        Ok(())
    }
}

pub struct TracedProcess {
    pub pid: Pid,
    pub saved_regs: user_regs_struct,
    /// Other threads we stopped (for multi-threaded processes)
    pub stopped_threads: Vec<Pid>,
}

impl TracedProcess {
    /// Get all thread IDs for a process
    fn get_thread_ids(pid: i32) -> Result<Vec<i32>> {
        let task_dir = format!("/proc/{}/task", pid);
        let entries = fs::read_dir(&task_dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ProcessNotFound { pid }
            } else {
                Error::Io(e)
            }
        })?;

        let mut tids = Vec::new();
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(tid) = name.parse::<i32>() {
                    tids.push(tid);
                }
            }
        }
        Ok(tids)
    }

    /// Attach to a process, stopping all threads
    pub fn attach(pid: Pid) -> Result<Self> {
        let pid_raw = pid.as_raw();

        // Get all thread IDs
        let tids = Self::get_thread_ids(pid_raw)?;

        // Attach to main thread first
        ptrace::attach(pid).map_err(|errno| {
            if errno == nix::errno::Errno::ESRCH {
                Error::ProcessNotFound { pid: pid_raw }
            } else {
                Error::AttachFailed { pid: pid_raw, source: errno }
            }
        })?;

        // Wait for main thread to stop
        match waitpid(pid, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {}
            Ok(status) => {
                let _ = ptrace::detach(pid, None);
                return Err(Error::UnexpectedWaitStatus(format!("{:?}", status).len() as i32));
            }
            Err(e) => {
                let _ = ptrace::detach(pid, None);
                return Err(Error::Ptrace(e));
            }
        }

        // Stop all other threads
        let mut stopped_threads = Vec::new();
        for &tid in &tids {
            if tid == pid_raw {
                continue; // Skip main thread (already attached)
            }

            let thread_pid = Pid::from_raw(tid);
            if ptrace::attach(thread_pid).is_ok() {
                // Wait for thread to stop
                if let Ok(WaitStatus::Stopped(_, _)) = waitpid(thread_pid, None) {
                    stopped_threads.push(thread_pid);
                } else {
                    let _ = ptrace::detach(thread_pid, None);
                }
            }
        }

        // Save original registers
        let saved_regs = ptrace_getregs(pid).map_err(Error::Ptrace)?;

        Ok(Self { pid, saved_regs, stopped_threads })
    }

    /// Get current registers
    pub fn getregs(&self) -> Result<user_regs_struct> {
        ptrace_getregs(self.pid).map_err(Error::Ptrace)
    }

    /// Set registers
    pub fn setregs(&self, regs: user_regs_struct) -> Result<()> {
        ptrace_setregs(self.pid, regs).map_err(Error::Ptrace)
    }

    /// Read memory from target process
    #[allow(dead_code)]
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        let mut offset = 0usize;

        while offset < len {
            let word = ptrace::read(self.pid, (addr + offset as u64) as *mut _)
                .map_err(Error::Ptrace)?;

            let bytes = word.to_ne_bytes();
            let remaining = len - offset;
            let to_copy = remaining.min(std::mem::size_of::<i64>());
            data.extend_from_slice(&bytes[..to_copy]);
            offset += std::mem::size_of::<i64>();
        }

        data.truncate(len);
        Ok(data)
    }

    /// Write memory to target process
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        let word_size = std::mem::size_of::<i64>();

        while offset < data.len() {
            let remaining = data.len() - offset;
            let word: i64 = if remaining >= word_size {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[offset..offset + word_size]);
                i64::from_ne_bytes(bytes)
            } else {
                // Partial word: read existing, merge, write back
                let existing = ptrace::read(self.pid, (addr + offset as u64) as *mut _)
                    .map_err(Error::Ptrace)?;
                let mut bytes = existing.to_ne_bytes();
                bytes[..remaining].copy_from_slice(&data[offset..]);
                i64::from_ne_bytes(bytes)
            };

            ptrace::write(self.pid, (addr + offset as u64) as *mut _, word)
                .map_err(Error::Ptrace)?;
            offset += word_size;
        }

        Ok(())
    }

    /// Restore registers and detach all threads
    pub fn detach(self) -> Result<()> {
        // Restore original registers for main thread
        ptrace_setregs(self.pid, self.saved_regs).map_err(Error::Ptrace)?;

        // Detach all other threads first
        for thread_pid in &self.stopped_threads {
            let _ = ptrace::detach(*thread_pid, None);
        }

        // Detach main thread
        ptrace::detach(self.pid, None).map_err(|e| Error::DetachFailed {
            pid: self.pid.as_raw(),
            source: e,
        })?;

        Ok(())
    }
}
