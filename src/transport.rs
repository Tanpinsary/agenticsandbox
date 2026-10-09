use crate::{
    error::{Error, Result, check},
    isolation,
};
use std::{
    io::{Read, Write},
    os::unix::io::AsRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Concurrent nonblocking pipe I/O prevents stdin/stdout deadlock, bounds
/// memory, and reaps the CLI and its local process group on every exit path.
pub fn bounded(cmd: &mut Command, data: &[u8], seconds: u64, limit: u64) -> Result<(i32, Vec<u8>)> {
    check(
        seconds > 0 && limit > 0,
        "Invalid transport limit",
        "configuration_error",
        500,
    )?;
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let result = (|| {
        let mut input = child.stdin.take();
        let mut output = child.stdout.take().unwrap();
        for fd in [input.as_ref().unwrap().as_raw_fd(), output.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut sent = 0;
        let mut bytes = Vec::new();
        let mut eof = false;
        let mut code = None;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::new(
                    "Worker transport timed out",
                    "worker_transport",
                    503,
                ));
            }
            if sent == data.len() {
                input = None;
            }
            if let Some(stdin) = input.as_mut() {
                match stdin.write(&data[sent..data.len().min(sent + 65536)]) {
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => input = None,
                    Err(e) => return Err(e.into()),
                }
            }
            if !eof {
                let mut buf = [0u8; 65536];
                let cap =
                    (limit.saturating_sub(bytes.len() as u64) + 1).min(buf.len() as u64) as usize;
                match output.read(&mut buf[..cap]) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        check(
                            bytes.len() as u64 + n as u64 <= limit,
                            "Worker response exceeds size limit",
                            "payload_too_large",
                            502,
                        )?;
                        bytes.extend_from_slice(&buf[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if code.is_none() {
                code = child.try_wait()?.map(|s| s.code().unwrap_or(-1));
            }
            if eof && let Some(code) = code {
                return Ok((code, bytes));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    isolation::kill_group(pid, libc::SIGKILL);
    let _ = child.wait();
    result
}
