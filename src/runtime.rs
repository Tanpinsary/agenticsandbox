use crate::{
    config::pinned_image,
    error::{Error, Result, check, ensure},
    util::*,
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};
pub const SOURCE_SHA: &str = env!("AGENTICSANDBOX_SOURCE_SHA256");
pub fn architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        arch => arch,
    }
}
fn tool_versions() -> Result<Value> {
    let mut tools = json!({});
    for tool in ["node", "npm"] {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("--version").stderr(std::process::Stdio::null());
        crate::isolation::session(&mut cmd);
        let (code, data) = crate::transport::bounded(&mut cmd, &[], 20, 65536)?;
        ensure(code == 0, "Cannot inspect preinstalled tool")?;
        tools[tool] = json!(String::from_utf8_lossy(&data).trim());
    }
    Ok(tools)
}
pub fn manifest_path() -> std::path::PathBuf {
    std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(Path::new("."))
        .join("runtime-manifest.json")
}
pub fn build_manifest(base: &str, node: &str, output: &Path) -> Result<()> {
    ensure(
        pinned_image(base) && pinned_image(node),
        "Specify complete base image digests",
    )?;
    let exe = std::env::current_exe()?;
    let value = json!({"schema_version":3,"implementation":"rust","worker_protocol_version":crate::WORKER_PROTOCOL,"worker_version":crate::VERSION,"worker_source_sha256":SOURCE_SHA,"worker_binary_sha256":digest(&fs::read(exe)?),"base_image":base,"node_image":node,"image_name":"agentic-container","os":std::env::consts::OS,"architecture":architecture(),"task_uid":10001,"tools":tool_versions()?});
    atomic(output, &canonical(&value), 0o444)
}
pub fn identity() -> Result<Value> {
    let mut value = json!({"worker_protocol_version":crate::WORKER_PROTOCOL,"worker_version":crate::VERSION,"implementation":"rust","worker_source_sha256":SOURCE_SHA,"runtime_manifest_verified":false,"os":std::env::consts::OS,"architecture":architecture()});
    let path = manifest_path();
    if !path.exists() {
        return Ok(value);
    }
    ensure(
        !path.is_symlink() && path.is_file(),
        "Invalid runtime manifest path",
    )?;
    let data = read_limit(fs::File::open(path)?, 65536)?;
    let m: Value = serde_json::from_slice(&data)?;
    check(
        m["schema_version"] == 3
            && m["implementation"] == "rust"
            && [
                "worker_protocol_version",
                "worker_version",
                "worker_source_sha256",
                "os",
                "architecture",
            ]
            .iter()
            .all(|k| m[*k] == value[*k])
            && m["task_uid"] == 10001
            && m["worker_binary_sha256"] == digest(&fs::read(std::env::current_exe()?)?)
            && m["tools"] == tool_versions()?
            && pinned_image(&s(&m, "base_image"))
            && pinned_image(&s(&m, "node_image")),
        "Runtime differs from build manifest",
        "runtime_manifest",
        409,
    )?;
    value["runtime_manifest_verified"] = json!(true);
    value["runtime_manifest_sha256"] = json!(digest(&data));
    value["runtime_task_uid"] = json!(10001);
    value["runtime_manifest"] = m;
    Ok(value)
}
pub fn validate_identity(v: &Value, p: &Value) -> Result<()> {
    check(
        v["control_uid"] == 0 && v["image_digest"] == p["image_digest"],
        "Worker identity differs from audited profile",
        "unverified_runtime",
        409,
    )?;
    check(
        v["worker_protocol_version"] == crate::WORKER_PROTOCOL,
        "Incompatible worker protocol",
        "incompatible_worker",
        409,
    )?;
    check(
        v["implementation"] == "rust"
            && b(v, "runtime_manifest_verified")
            && v["os"] == "linux"
            && v["runtime_task_uid"] == n(p, "task_uid", 10001)
            && v["worker_source_sha256"]
                == p["worker_source_sha256"].as_str().unwrap_or(SOURCE_SHA),
        "Worker build differs from approved runtime",
        "unverified_runtime",
        409,
    )?;
    for k in ["runtime_manifest_sha256", "architecture"] {
        if p.get(k).is_some() {
            check(
                v[k] == p[k],
                "Worker manifest or architecture differs",
                "unverified_runtime",
                409,
            )?;
        }
    }
    Ok(())
}
pub fn pid_limit(root: &Path) -> Result<u64> {
    for p in [root.join("pids.max"), root.join("pids/pids.max")] {
        match fs::read_to_string(p) {
            Ok(value) => {
                let value = value.trim();
                let limit = value.parse::<u64>().unwrap_or(0);
                ensure(
                    !value.is_empty()
                        && value.len() <= 10
                        && value.bytes().all(|c| c.is_ascii_digit())
                        && (1..=128).contains(&limit),
                    "Container PID limit must be between 1 and 128",
                )?;
                return Ok(limit);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::new(
        "Container PID cgroup limit unavailable",
        "unverified_runtime",
        409,
    ))
}
pub fn storage(root: &Path, persistent: bool, namespace: Option<&str>) -> Result<Value> {
    ensure(
        !root.is_symlink() && root.is_dir(),
        "Workspace must be a real directory",
    )?;
    let meta = root.metadata()?;
    if unsafe { libc::getuid() } == 0 {
        ensure(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "Workspace root must be controller-owned",
        )?;
    }
    if persistent {
        let parent = root.parent().unwrap_or(root).metadata()?;
        ensure(
            parent.dev() != meta.dev() || parent.ino() == meta.ino(),
            "Persistent workspace requires a mounted volume",
        )?;
    }
    let namespace = match namespace {
        Some(namespace) => namespace.to_owned(),
        None => fs::read_link("/proc/self/ns/pid")?.display().to_string(),
    };
    let control = crate::worker::control(root)?;
    let _guard = lock(&control.join("storage.lock"))?;
    let path = control.join("storage.json");
    ensure(!path.is_symlink(), "Storage metadata cannot be a symlink")?;
    let previous = if path.exists() {
        Some(load(&path)?)
    } else {
        None
    };
    if let Some(p) = &previous {
        ensure(
            p["schema_version"] == 1 && p["task_uid"] == 10001,
            "Incompatible storage version or UID",
        )?;
    }
    let mut recovered = Vec::new();
    let executions = control.join("executions");
    ensure(
        !executions.is_symlink(),
        "Execution directory cannot be a symlink",
    )?;
    if previous
        .as_ref()
        .is_none_or(|p| p["pid_namespace"] != namespace)
        && executions.exists()
    {
        for e in fs::read_dir(&executions)? {
            let p = e?.path();
            if p.extension().is_none_or(|e| e != "json") {
                continue;
            }
            ensure(!p.is_symlink(), "Execution metadata cannot be a symlink")?;
            let mut record = load(&p)?;
            if matches!(record["state"].as_str(), Some("starting" | "running")) {
                let _lock = lock(&p.with_extension("lock"))?;
                record["state"] = json!("lost");
                record["completed_at"] = json!(now());
                record["error"] = json!("Workspace restarted; execution cannot resume");
                for key in ["pid", "supervisor_pid", "launch_pending"] {
                    record.as_object_mut().unwrap().remove(key);
                }
                save(&p, &record)?;
                recovered.push(p.file_stem().unwrap().to_string_lossy().to_string());
            }
        }
    }
    let mode = if persistent {
        "persistent"
    } else {
        "ephemeral"
    };
    save(
        &path,
        &json!({"schema_version":1,"task_uid":10001,"storage":mode,"pid_namespace":namespace,"started_at":now()}),
    )?;
    Ok(
        json!({"storage":mode,"interrupted_executions":recovered,"installed_input_preserved":control.join("install.json").is_file()}),
    )
}
pub fn probe(expected: u32) -> Result<Value> {
    ensure(
        expected >= 10000 && cfg!(target_os = "linux"),
        "Probe requires Linux and dedicated UID",
    )?;
    let status = fs::read_to_string("/proc/self/status")?;
    let fields: std::collections::BTreeMap<_, _> = status
        .lines()
        .filter_map(|s| s.split_once(':'))
        .map(|(k, v)| (k, v.trim()))
        .collect();
    let mut checks = json!({"task_uid":unsafe{libc::getuid()}==expected,"task_gid":unsafe{libc::getgid()}==expected,"no_supplementary_groups":unsafe{libc::getgroups(0,std::ptr::null_mut())}==0,"no_capabilities":(["CapEff","CapPrm","CapInh","CapAmb"].iter().all(|key|fields.get(key).is_some_and(|v|u64::from_str_radix(v,16)==Ok(0)))),"no_new_privileges":fields.get("NoNewPrivs")==Some(&"1"),"seccomp":fields.get("Seccomp")==Some(&"2"),"no_control_environment":!std::env::vars_os().any(|(k,_)|k.to_string_lossy().starts_with("CODER_")),"pid_cgroup_limit":pid_limit(Path::new("/sys/fs/cgroup")).is_ok(),"no_docker_socket":!Path::new("/var/run/docker.sock").exists()});
    for (label, path) in [
        ("control_private", "/workspace/control/install.json"),
        ("workspace_private", "/workspace/control"),
        ("root_environment_private", "/proc/1/environ"),
        ("control_tmp_private", "/tmp"),
        ("host_home_private", "/root"),
    ] {
        let p = Path::new(path);
        let result = if p.is_dir() {
            fs::read_dir(p).map(|_| ())
        } else {
            fs::File::open(p).map(|_| ())
        };
        checks[label] = json!(
            result.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied
                || label == "host_home_private" && e.kind() == std::io::ErrorKind::NotFound)
        );
    }
    for (label, domain) in [
        ("network_denied", libc::AF_INET),
        ("unix_socket_denied", libc::AF_UNIX),
    ] {
        let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
        checks[label] =
            json!(fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM));
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
    let mut pair = [0; 2];
    let rc = unsafe { libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    checks["internet_socketpair_denied"] =
        json!(rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM));
    if rc == 0 {
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
    }
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    let mut bytes = [0u8; 6];
    let ok = rc == 0
        && unsafe { libc::write(pair[1], b"signal".as_ptr().cast(), 6) } == 6
        && unsafe { libc::read(pair[0], bytes.as_mut_ptr().cast(), 6) } == 6
        && &bytes == b"signal";
    if rc == 0 {
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
    }
    checks["anonymous_unix_socketpair"] = json!(ok);
    Ok(json!({"passed":obj(&checks)?.values().all(|v|v==true),"checks":checks}))
}
