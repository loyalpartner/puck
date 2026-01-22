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

            ptrace::write(self.pid, chunk_addr as *mut _, word)
                .map_err(|e| Error::MemWriteFailed { addr: chunk_addr, source: e })?;
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
