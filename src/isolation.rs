use crate::error::{Result, ensure};
use std::{collections::BTreeMap, os::unix::process::CommandExt, path::Path, process::Command};

pub fn environment(root: &Path) -> BTreeMap<String, String> {
    let mut env: BTreeMap<_, _> = [
        ("LANG", "C.UTF-8"),
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("NPM_CONFIG_UPDATE_NOTIFIER", "false"),
        ("DISABLE_AUTOUPDATER", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_AUTHOR_NAME", "Task"),
        ("GIT_AUTHOR_EMAIL", "task@agenticsandbox.invalid"),
        ("GIT_COMMITTER_NAME", "Task"),
        ("GIT_COMMITTER_EMAIL", "task@agenticsandbox.invalid"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    for (key, path) in [
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("NPM_CONFIG_PREFIX", "home/.local"),
        ("NPM_CONFIG_CACHE", "home/.npm"),
        ("DSH_HOME", "home/.dsh"),
    ] {
        env.insert(key.into(), root.join(path).display().to_string());
    }
    // Some harnesses drop environment names with numeric suffixes, leaving
    // GIT_CONFIG_COUNT without its keys. Git's quoted parameter form survives
    // those filters and still permits read-only verification repositories.
    let safe = format!("safe.directory={}", root.join("repo").display());
    env.insert(
        "GIT_CONFIG_PARAMETERS".into(),
        format!("'{}'", safe.replace('\'', "'\\''")),
    );
    env.insert(
        "PATH".into(),
        format!(
            "{}:{}:/usr/local/bin:/usr/bin:/bin",
            root.join("home/.local/bin").display(),
            root.join("harnesses/bin").display()
        ),
    );
    env
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct ArgCompare {
    arg: u32,
    op: i32,
    a: u64,
    b: u64,
}
#[cfg(target_os = "linux")]
#[link(name = "seccomp")]
unsafe extern "C" {
    fn seccomp_init(action: u32) -> *mut libc::c_void;
    fn seccomp_release(ctx: *mut libc::c_void);
    fn seccomp_syscall_resolve_name(name: *const libc::c_char) -> i32;
    fn seccomp_rule_add_array(
        ctx: *mut libc::c_void,
        action: u32,
        syscall: i32,
        count: u32,
        args: *const ArgCompare,
    ) -> i32;
    fn seccomp_export_bpf(ctx: *mut libc::c_void, fd: i32) -> i32;
}

/// Compile seccomp in the parent. The post-fork hook only calls raw syscalls;
/// it performs no allocation, locking, dynamic loading or environment access.
pub fn restrict(command: &mut Command, uid: Option<u32>, mode: &str, session: bool) -> Result<()> {
    ensure(
        matches!(mode, "deny" | "external-audit"),
        "Unknown task network enforcement",
    )?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, uid, session);
        Err(crate::error::Error::new(
            "Production restrictions require Linux",
            "unverified_runtime",
            409,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::{Read, Seek};
        use std::os::unix::io::AsRawFd;
        let ctx = unsafe { seccomp_init(0x7fff0000) };
        ensure(!ctx.is_null(), "Cannot initialize seccomp")?;
        let compiled = (|| -> Result<Vec<libc::sock_filter>> {
            let mut denied = vec![
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
                "bpf",
                "perf_event_open",
                "keyctl",
                "add_key",
                "request_key",
                "mount",
                "umount2",
                "pivot_root",
                "unshare",
                "setns",
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
            ];
            if mode == "deny" {
                denied.extend([
                    "socket", "connect", "bind", "listen", "accept", "accept4", "sendto",
                    "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
                ]);
            }
            for name in denied {
                let name = std::ffi::CString::new(name).unwrap();
                let number = unsafe { seccomp_syscall_resolve_name(name.as_ptr()) };
                ensure(
                    number < 0
                        || unsafe {
                            seccomp_rule_add_array(
                                ctx,
                                0x50000 | libc::EPERM as u32,
                                number,
                                0,
                                std::ptr::null(),
                            )
                        } == 0,
                    "Cannot install seccomp rule",
                )?;
            }
            if mode == "deny" {
                let cmp = ArgCompare {
                    arg: 0,
                    op: 1,
                    a: libc::AF_UNIX as u64,
                    b: 0,
                };
                let number = unsafe { seccomp_syscall_resolve_name(c"socketpair".as_ptr()) };
                ensure(
                    number >= 0
                        && unsafe {
                            seccomp_rule_add_array(
                                ctx,
                                0x50000 | libc::EPERM as u32,
                                number,
                                1,
                                &cmp,
                            )
                        } == 0,
                    "Cannot restrict socketpair",
                )?;
            }
            let mut f = tempfile::tempfile()?;
            ensure(
                unsafe { seccomp_export_bpf(ctx, f.as_raw_fd()) } == 0,
                "Cannot export seccomp",
            )?;
            f.rewind()?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            let size = std::mem::size_of::<libc::sock_filter>();
            ensure(
                bytes.len() % size == 0 && bytes.len() / size <= u16::MAX as usize,
                "Invalid seccomp filter",
            )?;
            Ok(bytes
                .chunks_exact(size)
                .map(|chunk| unsafe {
                    std::ptr::read_unaligned(chunk.as_ptr().cast::<libc::sock_filter>())
                })
                .collect())
        })();
        unsafe { seccomp_release(ctx) };
        let filter = compiled?;
        // SAFETY: filter is built before fork and owned by this closure. Only
        // async-signal-safe syscalls and nonallocating Error::from_raw_os_error
        // are used after fork. The kernel copies the BPF program during prctl.
        unsafe {
            command.pre_exec(move || {
                if session && libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(uid) = uid
                    && (libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(uid) != 0
                        || libc::setuid(uid) != 0)
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let prog = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr() as *mut _,
                };
                if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}
pub fn session(command: &mut Command) {
    // SAFETY: setsid is a raw, async-signal-safe syscall with no borrowed state.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}
pub fn kill_group(pid: u32, signal: i32) {
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

pub fn chown_tree(root: &Path, uid: Option<u32>, readonly: bool) -> Result<()> {
    let Some(uid) = uid else { return Ok(()) };
    ensure(
        unsafe { libc::getuid() } == 0,
        "Production worker requires controller identity",
    )?;
    fn visit(path: &Path, owner: u32, readonly: bool) -> Result<()> {
        let m = std::fs::symlink_metadata(path)?;
        ensure(!m.file_type().is_symlink(), "Symlink in installed tree")?;
        if m.is_dir() {
            for e in std::fs::read_dir(path)? {
                visit(&e?.path(), owner, readonly)?;
            }
        }
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        };
        if m.is_dir() || readonly {
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(if m.is_dir() || m.mode() & 0o100 != 0 {
                    0o755
                } else {
                    0o644
                }),
            )?;
        }
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| crate::error::Error::new("Invalid path", "invalid_request", 400))?;
        if unsafe { libc::chown(c.as_ptr(), owner, owner) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    for name in ["repo", "tmp", "build", "home"] {
        let path = root.join(name);
        if path.exists() {
            visit(
                &path,
                if name == "repo" && readonly { 0 } else { uid },
                name == "repo" && readonly,
            )?;
        }
    }
    Ok(())
}
