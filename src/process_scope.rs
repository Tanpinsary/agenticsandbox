//! Each detached supervisor is a Linux subreaper. Orphaned descendants stay in
//! this execution's scope even after setsid, setpgid or a double fork. pidfds
//! avoid signalling a recycled PID belonging to another execution.
use crate::error::Result;
#[cfg(target_os = "linux")]
use crate::error::ensure;

pub struct ProcessScope;

impl ProcessScope {
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{FromRawFd, OwnedFd};
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
            ensure(fd >= 0, "Execution scopes require Linux pidfd support")?;
            drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
            if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(Self)
    }

    #[cfg(target_os = "linux")]
    fn children(&self) -> Result<Vec<i32>> {
        let path = format!("/proc/self/task/{}/children", unsafe {
            libc::syscall(libc::SYS_gettid)
        });
        let text = std::fs::read_to_string(path)?;
        text.split_whitespace()
            .map(|v| {
                v.parse::<i32>().map_err(|_| {
                    crate::error::Error::new("Invalid child PID", "internal_error", 500)
                })
            })
            .collect()
    }

    pub fn signal(&self, main: u32, signal: i32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            let _ = main;
            for pid in self.children()? {
                let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if raw < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) {
                        continue;
                    }
                    return Err(error.into());
                }
                let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
                // Recheck ownership after opening the stable handle. Another
                // supervisor's process can never become our direct child.
                let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                    continue;
                };
                if !status.lines().any(|line| {
                    line.strip_prefix("PPid:")
                        .is_some_and(|v| v.trim() == std::process::id().to_string())
                }) {
                    continue;
                }
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        signal,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error.into());
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        crate::isolation::kill_group(main, signal);
        Ok(())
    }

    /// Reap adopted children without consuming std::process::Child's main
    /// process status. Completion is true only after every descendant is gone.
    pub fn reap(&self, main: Option<u32>) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            for pid in self.children()? {
                if main == Some(pid as u32) {
                    continue;
                }
                let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
                if result < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            Ok(self.children()?.is_empty())
        }
        #[cfg(not(target_os = "linux"))]
        Ok(main.is_none())
    }
}
