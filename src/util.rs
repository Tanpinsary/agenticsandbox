use crate::error::{Result, check, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("JSON value serialization")
}
pub fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}
pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 48]>())
}
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
pub fn s(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or("").to_owned()
}
pub fn n(v: &Value, key: &str, default: u64) -> u64 {
    v[key].as_u64().unwrap_or(default)
}
pub fn b(v: &Value, key: &str) -> bool {
    v[key] == true
}
pub fn obj(v: &Value) -> Result<&serde_json::Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| crate::error::Error::new("Expected an object", "invalid_request", 400))
}
pub fn strings(v: &Value) -> Result<Vec<String>> {
    let a = v.as_array().ok_or_else(|| {
        crate::error::Error::new("Expected a string array", "invalid_request", 400)
    })?;
    a.iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| {
                    crate::error::Error::new("Expected a string array", "invalid_request", 400)
                })
        })
        .collect()
}
pub fn decode(v: &Value, limit: u64) -> Result<Vec<u8>> {
    let text = v.as_str().unwrap_or("");
    ensure(
        v.is_string() && text.len() as u64 <= limit.saturating_mul(4) / 3 + 8,
        "Payload too large or invalid",
    )?;
    let result = STANDARD
        .decode(text)
        .map_err(|_| crate::error::Error::new("Invalid base64 payload", "invalid_request", 400))?;
    ensure(result.len() as u64 <= limit, "Payload too large")?;
    Ok(result)
}
pub fn relative(path: &str) -> Result<&str> {
    ensure(
        !path.is_empty() && !path.starts_with('/') && !path.contains(['\0', '\\', ':']),
        "Expected a relative path",
    )?;
    ensure(
        path.split('/').all(|p| {
            !matches!(p, "" | "." | "..")
                && !matches!(p.to_lowercase().as_str(), ".git" | ".agenticsandbox")
        }),
        "Path traversal or reserved path",
    )?;
    Ok(path)
}
pub fn sha(value: &str) -> Result<&str> {
    ensure(
        matches!(value.len(), 40 | 64)
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "Expected a full Git object ID",
    )?;
    Ok(value)
}
pub fn checksum(value: &str) -> bool {
    value.len() == 64 && sha(value).is_ok()
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        crate::error::Error::new("Missing parent directory", "invalid_request", 400)
    })?;
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| crate::error::Error::from(e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn save(path: &Path, v: &Value) -> Result<()> {
    atomic(path, &canonical(v), 0o600)
}
pub fn load(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read_limit(
        File::open(path)?,
        384 * 1024 * 1024,
    )?)?)
}
pub fn read_limit(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data)?;
    check(
        data.len() as u64 <= limit,
        "Payload exceeds size limit",
        "payload_too_large",
        413,
    )?;
    Ok(data)
}
pub fn lock(path: &Path) -> Result<File> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    // SAFETY: the descriptor belongs to file and remains live for the lock lifetime.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    check(
        status == 0,
        "Another process owns this lock",
        "controller_running",
        409,
    )?;
    Ok(file)
}
pub fn safe_open(
    root: &Path,
    path: &str,
    flags: i32,
    create: bool,
    owner: Option<u32>,
) -> Result<File> {
    relative(path)?;
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)?;
    let parts: Vec<_> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let part = std::ffi::CString::new(*part).expect("validated path");
        let last = i + 1 == parts.len();
        // SAFETY: dir is live, part is NUL-terminated; each opened descriptor is
        // immediately owned by a File. O_NOFOLLOW applies to every component.
        let created =
            !last && create && unsafe { libc::mkdirat(dir.as_raw_fd(), part.as_ptr(), 0o755) } == 0;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                part.as_ptr(),
                libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | if last {
                        flags
                    } else {
                        libc::O_RDONLY | libc::O_DIRECTORY
                    },
                0o644,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        if created && unsafe { libc::fchmod(fd, 0o755) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if create
            && !last
            && let Some(uid) = owner
        {
            let rc = unsafe { libc::fchown(fd, uid, uid) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if last {
            return Ok(next);
        }
        dir = next;
    }
    unreachable!()
}
pub fn file_item(data: &[u8], executable: bool) -> Value {
    json!({"mode": if executable {"100755"} else {"100644"}, "data": encode(data), "sha256": digest(data)})
}
pub fn regular(file: &File, single_link: bool) -> Result<()> {
    let m = file.metadata()?;
    ensure(
        m.is_file() && (!single_link || m.nlink() == 1),
        "Expected a regular file without hardlinks",
    )
}
pub fn absolute(base: &Path, path: &str) -> PathBuf {
    let joined = base.join(path);
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            _ => out.push(c.as_os_str()),
        }
    }
    out
}

#[derive(Clone)]
pub struct Policy {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    includes: Vec<regex::Regex>,
    excludes: Vec<regex::Regex>,
}
fn glob(pattern: &str) -> Result<regex::Regex> {
    relative(pattern)?;
    ensure(pattern.len() <= 512, "Invalid file pattern")?;
    let mut out = String::from("^");
    let mut rest = pattern;
    while !rest.is_empty() {
        if let Some(next) = rest.strip_prefix("**/") {
            out.push_str("(?:.*/)?");
            rest = next;
        } else if let Some(next) = rest.strip_prefix("**") {
            out.push_str(".*");
            rest = next;
        } else {
            let ch = rest.chars().next().unwrap();
            out.push_str(&match ch {
                '*' => "[^/]*".into(),
                '?' => "[^/]".into(),
                _ => regex::escape(&ch.to_string()),
            });
            rest = &rest[ch.len_utf8()..];
        }
    }
    out.push('$');
    regex::Regex::new(&out)
        .map_err(|_| crate::error::Error::new("Invalid pattern", "invalid_request", 400))
}
impl Policy {
    pub fn parse(v: &Value) -> Result<Self> {
        ensure(
            obj(v)?
                .keys()
                .all(|k| matches!(k.as_str(), "include" | "exclude")),
            "Unknown file policy field",
        )?;
        let include = strings(v.get("include").unwrap_or(&json!([])))?;
        let exclude = strings(v.get("exclude").unwrap_or(&json!([])))?;
        ensure(
            include.len() <= 256 && exclude.len() <= 256,
            "Too many file patterns",
        )?;
        let includes = include.iter().map(|p| glob(p)).collect::<Result<_>>()?;
        let excludes = exclude.iter().map(|p| glob(p)).collect::<Result<_>>()?;
        Ok(Self {
            include,
            exclude,
            includes,
            excludes,
        })
    }
    pub fn all() -> Self {
        Self::parse(&json!({"include":["**"]})).unwrap()
    }
    pub fn allows(&self, path: &str) -> Result<bool> {
        relative(path)?;
        Ok(self.includes.iter().any(|r| r.is_match(path))
            && !self.excludes.iter().any(|r| r.is_match(path)))
    }
    pub fn json(&self) -> Value {
        json!({"include":self.include,"exclude":self.exclude})
    }
    pub fn child(&self, v: &Value) -> Result<Self> {
        let mut child = Self::parse(v)?;
        check(
            child.include.iter().all(|p| self.include.contains(p)),
            "Child cannot widen file access",
            "forbidden",
            403,
        )?;
        child.exclude.extend(self.exclude.clone());
        Self::parse(&child.json())
    }
}
