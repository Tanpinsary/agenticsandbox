use crate::{
    error::{Error, Result, check, ensure},
    git, isolation,
    util::*,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub const MAX_REQUEST: u64 = 384 * 1024 * 1024;
pub fn record_path(root: &Path, id: &str) -> Result<PathBuf> {
    ensure(
        !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()),
        "Invalid execution ID",
    )?;
    Ok(root.join("control/executions").join(format!("{id}.json")))
}
pub fn control(root: &Path) -> Result<PathBuf> {
    let p = root.join("control");
    ensure(!p.is_symlink(), "Control directory cannot be a symlink")?;
    private_dir(&p)?;
    Ok(p)
}
pub fn working(root: &Path, policy: &Policy, limits: &Value) -> Result<(Value, Value)> {
    let repo = root.join("repo");
    let mut stack = vec![repo.clone()];
    let mut files = json!({});
    let mut omitted = Vec::new();
    let mut total = 0;
    let mut visited = 0;
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(dir)? {
            let e = e?;
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_lowercase();
            if matches!(name.as_str(), ".git" | ".agenticsandbox") {
                continue;
            }
            visited += 1;
            ensure(
                visited <= n(limits, "max_scan_entries", 100000),
                "Scan limit exceeded",
            )?;
            let m = fs::symlink_metadata(&path)?;
            ensure(!m.file_type().is_symlink(), "Symlinks unsupported")?;
            if m.is_dir() {
                stack.push(path);
                continue;
            }
            ensure(m.is_file(), "Special files unsupported")?;
            let rel =
                path.strip_prefix(&repo).unwrap().to_str().ok_or_else(|| {
                    Error::new("Non UTF-8 paths unsupported", "invalid_request", 400)
                })?;
            if !policy.allows(rel)? {
                omitted.push(rel.to_owned());
                continue;
            }
            ensure(
                (obj(&files)?.len() as u64) < n(limits, "max_files", 10000),
                "Too many files",
            )?;
            let file = safe_open(&repo, rel, libc::O_RDONLY | libc::O_NONBLOCK, false, None)?;
            regular(&file, false)?;
            let executable = file.metadata()?.mode() & 0o100 != 0;
            let data = read_limit(file, n(limits, "max_file_bytes", 8388608))?;
            total += data.len() as u64;
            ensure(
                total <= n(limits, "max_total_bytes", 67108864),
                "Snapshot exceeds total size",
            )?;
            files[rel] = file_item(&data, executable);
        }
    }
    git::validate_files(&files, limits)?;
    omitted.sort();
    Ok((files, json!(omitted)))
}
fn clear(repo: &Path) -> Result<()> {
    for e in fs::read_dir(repo)? {
        let e = e?;
        if e.file_name() == ".git" {
            continue;
        }
        if e.file_type()?.is_dir() {
            fs::remove_dir_all(e.path())?;
        } else {
            fs::remove_file(e.path())?;
        }
    }
    Ok(())
}
fn uid(v: &Value) -> Result<Option<u32>> {
    if v.is_null() {
        return Ok(None);
    }
    let value = v
        .as_u64()
        .filter(|n| *n >= 10000 && *n <= u32::MAX as u64)
        .ok_or_else(|| Error::new("Invalid task UID", "invalid_request", 400))?;
    Ok(Some(value as u32))
}

pub fn dispatch(root: &Path, op: &str, req: &Value) -> Result<Value> {
    obj(req)?;
    let installed = root.join("control/install.json");
    let scope =
        if !matches!(op, "identity" | "install" | "install_repository") && installed.exists() {
            let v = load(&installed)?;
            Some(git::Scope::new(
                root,
                uid(&v["task_uid"])?,
                b(&v, "read_only_source"),
            ))
        } else {
            None
        };
    let result = dispatch_inner(root, op, req);
    drop(scope);
    result
}
fn dispatch_inner(root: &Path, op: &str, req: &Value) -> Result<Value> {
    let repo = root.join("repo");
    match op {
        "identity" => {
            let mut value = crate::runtime::identity()?;
            value["image_digest"] = std::env::var("AGENTICSANDBOX_IMAGE_DIGEST")
                .map(Value::String)
                .unwrap_or(Value::Null);
            value["control_uid"] = json!(unsafe { libc::getuid() });
            Ok(value)
        }
        "install" | "install_repository" => {
            fs::create_dir_all(root)?;
            let control = control(root)?;
            let _lock = lock(&control.join("install.lock"))?;
            let manifest = control.join("install.json");
            let fingerprint = digest(&canonical(&if op == "install" {
                json!({"mode":"snapshot","files":req["files"],"task_uid":req["task_uid"],"read_only_source":req["read_only_source"]})
            } else {
                json!({"mode":"repository","base_sha":req["base_sha"],"bundle_sha256":req["bundle_sha256"],"task_uid":req["task_uid"],"read_only_source":req["read_only_source"]})
            }));
            if manifest.exists() {
                let value = load(&manifest)?;
                check(
                    value["fingerprint"] == fingerprint,
                    "Installed input differs from retry",
                    "conflict",
                    409,
                )?;
                return Ok(json!({"baseline_sha":value["baseline_sha"]}));
            }
            let task_uid = uid(&req["task_uid"])?;
            let readonly = b(req, "read_only_source");
            if task_uid.is_some() {
                ensure(
                    unsafe { libc::getuid() } == 0,
                    "Production worker requires root controller",
                )?;
            }
            for name in ["tmp", "build", "home"] {
                let p = root.join(name);
                ensure(!p.is_symlink(), "Workspace directory cannot be a symlink")?;
                fs::create_dir_all(p)?;
            }
            if repo.exists() || repo.is_symlink() {
                ensure(!repo.is_symlink(), "Repository cannot be a symlink")?;
                fs::remove_dir_all(&repo)?;
            }
            let baseline = if op == "install" {
                git::validate_files(&req["files"], &req["limits"])?;
                git::initialize(&repo, &req["files"])?
            } else {
                let base = s(req, "base_sha");
                sha(&base)?;
                let data = decode(
                    &req["bundle"],
                    n(&req["limits"], "max_bundle_bytes", 67108864),
                )?;
                check(
                    req["bundle_sha256"] == digest(&data),
                    "Input bundle checksum mismatch",
                    "corrupt_artifact",
                    409,
                )?;
                let bundle = control.join("input.bundle");
                atomic(&bundle, &data, 0o600)?;
                let bundle = bundle.display().to_string();
                git::run(
                    root,
                    &[
                        "clone",
                        "--no-local",
                        "--no-tags",
                        "--no-checkout",
                        "--template=",
                        &bundle,
                        &repo.display().to_string(),
                    ],
                )?;
                git::run(&repo, &["bundle", "verify", &bundle])?;
                check(
                    git::text(&repo, &["bundle", "list-heads", &bundle])?
                        .lines()
                        .any(|s| s.split_whitespace().next() == Some(&base)),
                    "Bundle does not contain requested base",
                    "corrupt_artifact",
                    409,
                )?;
                git::run(&repo, &["checkout", "--detach", &base])?;
                git::run(&repo, &["branch", "-f", "task", &base])?;
                git::run(&repo, &["checkout", "task"])?;
                git::run(&repo, &["remote", "remove", "origin"])?;
                ensure(
                    !repo.join(".git/objects/info/alternates").exists(),
                    "External object store forbidden",
                )?;
                base
            };
            isolation::chown_tree(root, task_uid, readonly)?;
            save(
                &manifest,
                &json!({"fingerprint":fingerprint,"baseline_sha":baseline,"task_uid":task_uid,"read_only_source":readonly}),
            )?;
            Ok(json!({"baseline_sha":baseline}))
        }
        "start" => {
            let path = record_path(root, &s(req, "id"))?;
            let _lock = lock(&path.with_extension("dispatch.lock"))?;
            let record = if path.exists() {
                let value = load(&path)?;
                check(
                    obj(req)?.iter().all(|(k, v)| value.get(k) == Some(v)),
                    "Execution ID reused with different request",
                    "conflict",
                    409,
                )?;
                if value["state"] != "starting" || b(&value, "launch_pending") {
                    return Ok(value);
                }
                value
            } else {
                let mut value = req.clone();
                value["state"] = json!("starting");
                value["created_at"] = json!(now());
                save(&path, &value)?;
                value
            };
            let mut cmd = Command::new(std::env::current_exe()?);
            cmd.arg("worker")
                .arg("supervise")
                .arg(root)
                .arg(s(req, "id"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .current_dir("/");
            isolation::session(&mut cmd);
            let mut child = cmd.spawn()?;
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            Ok(record)
        }
        "execution" | "logs" | "cancel" => {
            let path = record_path(root, &s(req, "id"))?;
            check(path.exists(), "Unknown execution", "not_found", 404)?;
            let mut value = load(&path)?;
            if (value["state"] == "running"
                || (value["state"] == "starting"
                    && (b(&value, "launch_pending")
                        || now() - value["created_at"].as_f64().unwrap_or(now()) > 10.0)))
                && let Ok(_lock) = lock(&path.with_extension("lock"))
            {
                value = load(&path)?;
                if matches!(value["state"].as_str(), Some("starting" | "running")) {
                    value["state"] = json!("lost");
                    value["completed_at"] = json!(now());
                    value["error"] = json!("Execution supervisor was lost");
                    save(&path, &value)?;
                }
            }
            if op == "cancel" {
                atomic(&path.with_extension("cancel"), b"cancel", 0o600)?;
                return Ok(value);
            }
            if op == "logs" {
                let cursor = req.get("cursor").unwrap_or(&Value::Null);
                ensure(
                    cursor.is_null() || cursor.as_u64().is_some(),
                    "Invalid log cursor",
                )?;
                let cursor = n(req, "cursor", 0);
                let log = path.with_extension("log");
                let data = if log.exists() {
                    let mut file = File::open(log)?;
                    file.seek(SeekFrom::Start(cursor))?;
                    let mut data = Vec::new();
                    file.take(65536).read_to_end(&mut data)?;
                    data
                } else {
                    vec![]
                };
                return Ok(
                    json!({"data":encode(&data),"cursor":cursor+data.len() as u64,"state":value["state"]}),
                );
            }
            Ok(value)
        }
        "read" | "write" | "search" => {
            let installed = load(&root.join("control/install.json"))?;
            check(
                op != "write" || !b(&installed, "read_only_source"),
                "Verification source is read-only",
                "forbidden",
                403,
            )?;
            task_files(root, op, req, &installed)
        }
        "export" | "checkpoint" => {
            let head = git::resolve(&repo, "HEAD")?;
            if let Some(base) = req["baseline_sha"].as_str() {
                check(
                    git::ancestor(&repo, base, &head)?,
                    "History no longer contains baseline",
                    "history_rewritten",
                    409,
                )?;
            }
            if op == "export" {
                check(
                    git::run(
                        &repo,
                        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
                    )?
                    .is_empty(),
                    "Submit requires committed changes",
                    "dirty_workspace",
                    409,
                )?;
            }
            let files = git::export(&repo, &head, &Policy::all(), &req["limits"])?;
            let mut value = json!({"sha":head,"files":files});
            if req["workspace_mode"] == "repository" {
                let bundle =
                    git::result_bundle(&repo, &s(req, "baseline_sha"), &head, &req["limits"])?;
                value["bundle"] = bundle
                    .as_ref()
                    .map(|b| json!(encode(b)))
                    .unwrap_or(Value::Null);
                value["bundle_sha256"] = bundle
                    .as_ref()
                    .map(|b| json!(digest(b)))
                    .unwrap_or(Value::Null);
            }
            if op == "export" {
                let mut commits = Vec::new();
                let mut total = 0;
                for revision in git::text(&repo, &["rev-list", "--max-count=101", &head])?.lines() {
                    if revision == s(req, "baseline_sha") {
                        break;
                    }
                    ensure(commits.len() < 100, "Too many task commits")?;
                    let size = git::text(&repo, &["cat-file", "-s", revision])?
                        .parse::<u64>()
                        .unwrap_or(u64::MAX);
                    ensure(size <= 100000, "Commit metadata too large")?;
                    total += size;
                    ensure(total <= 1048576, "Commit metadata too large")?;
                    commits.push(git::text(
                        &repo,
                        &[
                            "show",
                            "--no-patch",
                            "--format=%H%n%an%n%ae%n%aI%n%B",
                            revision,
                        ],
                    )?);
                }
                ensure(
                    git::text(&repo, &["cat-file", "-s", &head])?
                        .parse::<u64>()
                        .unwrap_or(u64::MAX)
                        <= 100000,
                    "Commit metadata too large",
                )?;
                value["commit_metadata"] = json!(git::text(
                    &repo,
                    &[
                        "show",
                        "--no-patch",
                        "--format=%H%n%an%n%ae%n%aI%n%B",
                        &head
                    ]
                )?);
                value["commits"] = json!(commits);
            } else {
                let policy = if req["workspace_mode"] == "repository" {
                    Policy::all()
                } else {
                    Policy::parse(&req["files"])?
                };
                let installed = load(&root.join("control/install.json"))?;
                let snapshot = task_files(
                    root,
                    "snapshot",
                    &json!({"files":policy.json(),"limits":req["limits"]}),
                    &installed,
                )?;
                value["working_files"] = snapshot["files"].clone();
                value["omitted"] = snapshot["omitted"].clone();
            }
            value["checksum"] = json!(digest(&canonical(&value)));
            Ok(value)
        }
        "restore" => {
            let path = root.join("control/restore.json");
            let fingerprint = digest(&canonical(req));
            if path.exists() {
                let v = load(&path)?;
                check(
                    v["fingerprint"] == fingerprint,
                    "Recovery input differs from retry",
                    "conflict",
                    409,
                )?;
                return Ok(json!({"sha":v["sha"]}));
            }
            let installed = load(&root.join("control/install.json"))?;
            let head = if let Some(task_uid) = uid(&installed["task_uid"])?
                && !b(&installed, "read_only_source")
            {
                // Filesystem recovery must also run as the installed task UID.
                // The container intentionally has no DAC_OVERRIDE or FOWNER.
                let result = restricted_helper(
                    root,
                    "recover",
                    &json!({"root":root,"request":req}),
                    task_uid,
                )?;
                s(&result, "sha")
            } else {
                let head = recover_files(root, req)?;
                isolation::chown_tree(
                    root,
                    uid(&installed["task_uid"])?,
                    b(&installed, "read_only_source"),
                )?;
                head
            };
            save(&path, &json!({"fingerprint":fingerprint,"sha":head}))?;
            Ok(json!({"sha":head}))
        }
        _ => Err(Error::new(
            "Unknown worker operation",
            "invalid_request",
            400,
        )),
    }
}

fn restricted_helper(root: &Path, mode: &str, req: &Value, task_uid: u32) -> Result<Value> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["worker", mode])
        .env_clear()
        .envs(isolation::environment(root))
        .stderr(Stdio::null());
    isolation::restrict(&mut command, Some(task_uid), "deny", true)?;
    let (code, data) = crate::transport::bounded(&mut command, &canonical(req), 120, MAX_REQUEST)?;
    check(
        code == 0,
        "Restricted task filesystem operation failed",
        "worker_error",
        409,
    )?;
    Ok(serde_json::from_slice(&data)?)
}
fn task_files(root: &Path, operation: &str, request: &Value, installed: &Value) -> Result<Value> {
    if let Some(task_uid) = uid(&installed["task_uid"])? {
        restricted_helper(
            root,
            "files",
            &json!({"root":root,"operation":operation,"request":request}),
            task_uid,
        )
    } else {
        filesystem(root, operation, request)
    }
}
/// Runs in the installed task identity, without access to private control data.
pub fn filesystem(root: &Path, op: &str, req: &Value) -> Result<Value> {
    let repo = root.join("repo");
    match op {
        "read" => {
            let f = safe_open(
                &repo,
                &s(req, "path"),
                libc::O_RDONLY | libc::O_NONBLOCK,
                false,
                None,
            )?;
            regular(&f, false)?;
            let data = read_limit(f, n(req, "limit", 8388608))?;
            Ok(json!({"data":encode(&data),"sha256":digest(&data)}))
        }
        "write" => {
            let data = decode(&req["data"], n(req, "limit", 8388608))?;
            let mut f = safe_open(
                &repo,
                &s(req, "path"),
                libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK,
                true,
                None,
            )?;
            regular(&f, true)?;
            f.set_len(0)?;
            f.write_all(&data)?;
            Ok(json!({"sha256":digest(&data),"bytes":data.len()}))
        }
        "search" => {
            let query = s(req, "query");
            ensure(
                !query.is_empty() && query.len() <= 1000,
                "Invalid search query",
            )?;
            let (files, _) = working(root, &Policy::parse(&req["files"])?, &req["limits"])?;
            let mut matches = Vec::new();
            for (path, item) in obj(&files)? {
                let data = decode(&item["data"], n(&req["limits"], "max_file_bytes", 8388608))?;
                if data.contains(&0) {
                    continue;
                }
                for (i, line) in String::from_utf8_lossy(&data).lines().enumerate() {
                    if line.contains(&query) {
                        matches.push(json!({"path":path,"line":i+1,"text":line.chars().take(2000).collect::<String>()}));
                        if matches.len() >= 1000 {
                            return Ok(json!({"matches":matches,"truncated":true}));
                        }
                    }
                }
            }
            Ok(json!({"matches":matches,"truncated":false}))
        }
        "snapshot" => {
            let (files, omitted) = working(root, &Policy::parse(&req["files"])?, &req["limits"])?;
            Ok(json!({"files":files,"omitted":omitted}))
        }
        _ => Err(Error::new(
            "Unknown task filesystem operation",
            "invalid_request",
            400,
        )),
    }
}

/// Invoked in an already restricted child for writable production workspaces.
/// The JSON payload contains frozen code only; no controller metadata is read.
pub fn recover_files(root: &Path, req: &Value) -> Result<String> {
    let repo = root.join("repo");
    git::validate_files(&req["committed_files"], &req["limits"])?;
    git::validate_files(&req["working_files"], &req["limits"])?;
    let before = git::export(
        &repo,
        &git::resolve(&repo, "HEAD")?,
        &Policy::all(),
        &req["limits"],
    )?;
    clear(&repo)?;
    if req["workspace_mode"] == "repository" {
        let bundle = if req["bundle"].is_null() {
            None
        } else {
            Some(decode(
                &req["bundle"],
                n(&req["limits"], "max_bundle_bytes", 67108864),
            )?)
        };
        git::receive(
            &repo,
            &s(req, "base_sha"),
            &s(req, "sha"),
            bundle.as_deref(),
            &req["bundle_sha256"],
            &Policy::parse(&req["files"])?,
            &req["committed_files"],
            &req["limits"],
        )?;
        git::run(&repo, &["update-ref", "refs/heads/task", &s(req, "sha")])?;
    } else {
        git::update_index(&repo, &before, &req["committed_files"])?;
        git::run(
            &repo,
            &[
                "commit",
                "--allow-empty",
                "-m",
                "Restore committed checkpoint state",
            ],
        )?;
    }
    git::run(&repo, &["reset", "--hard", "HEAD"])?;
    clear(&repo)?;
    git::write_files(&repo, &req["working_files"])?;
    git::resolve(&repo, "HEAD")
}

pub fn supervise(root: &Path, id: &str) -> Result<()> {
    let path = record_path(root, id)?;
    let Ok(_lock) = lock(&path.with_extension("lock")) else {
        return Ok(());
    };
    let mut record = load(&path)?;
    if !matches!(record["state"].as_str(), Some("starting" | "running")) {
        return Ok(());
    }
    if record["state"] == "running" || b(&record, "launch_pending") {
        record["state"] = json!("lost");
        record["completed_at"] = json!(now());
        return save(&path, &record);
    }
    let mut child = None;
    let mut scope = None;
    let result = (|| -> Result<()> {
        scope = Some(crate::process_scope::ProcessScope::new()?);
        let wd = record["work_dir"].as_str().unwrap_or("repo");
        ensure(matches!(wd, "repo" | "build"), "Invalid working directory")?;
        let mut work = root.join(wd);
        if let Some(cwd) = record["cwd"].as_str() {
            work = work.join(relative(cwd)?);
        }
        let work = fs::canonicalize(work)?;
        ensure(
            work.starts_with(fs::canonicalize(root)?),
            "Working directory escapes task",
        )?;
        let argv = strings(&record["argv"])?;
        ensure(!argv.is_empty() && argv.len() <= 256, "Invalid argv")?;
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(work)
            .env_clear()
            .envs(isolation::environment(root));
        if let Some(env) = record.get("environment") {
            for (k, v) in obj(env)? {
                ensure(v.is_string(), "Invalid environment")?;
                command.env(k, v.as_str().unwrap());
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(uid) = uid(&record["task_uid"])? {
            isolation::restrict(
                &mut command,
                Some(uid),
                record["network_mode"].as_str().unwrap_or("deny"),
                true,
            )?;
        } else {
            isolation::session(&mut command);
        }
        // SAFETY: stdio is already configured; dup2 is async-signal-safe.
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                if libc::dup2(1, 2) < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        record["launch_pending"] = json!(true);
        record["supervisor_pid"] = json!(std::process::id());
        record["heartbeat"] = json!(now());
        save(&path, &record)?;
        child = Some(command.spawn()?);
        let proc = child.as_mut().unwrap();
        let pid = proc.id();
        let mut output = proc.stdout.take().unwrap();
        unsafe {
            libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        }
        record["state"] = json!("running");
        record["pid"] = json!(pid);
        record["started_at"] = json!(now());
        record.as_object_mut().unwrap().remove("launch_pending");
        save(&path, &record)?;
        let mut log = File::create(path.with_extension("log"))?;
        let mut written = 0;
        let mut truncated = false;
        let mut reason = None;
        let mut kill_at = None;
        let mut eof = false;
        let mut status = None;
        let mut descendants_gone = false;
        let deadline = Instant::now() + Duration::from_secs(n(&record, "timeout_seconds", 300));
        let mut heartbeat = Instant::now();
        while !eof || status.is_none() || !descendants_gone {
            if reason.is_none()
                && (Instant::now() >= deadline || path.with_extension("cancel").exists())
            {
                reason = Some(if Instant::now() >= deadline {
                    "timeout"
                } else {
                    "cancelled"
                });
                kill_at = Some(Instant::now() + Duration::from_secs(2));
                record["termination_reason"] = json!(reason);
            }
            if status.is_some() && kill_at.is_none() {
                // A successful main command must not leave a daemon behind.
                kill_at = Some(Instant::now() + Duration::from_secs(2));
            }
            if let Some(at) = kill_at {
                scope.as_ref().unwrap().signal(
                    pid,
                    if Instant::now() >= at {
                        libc::SIGKILL
                    } else {
                        libc::SIGTERM
                    },
                )?;
            }
            if !eof {
                let mut buf = [0; 65536];
                match output.read(&mut buf) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        let accepted = count.min(
                            n(&record, "max_output_bytes", 4194304).saturating_sub(written)
                                as usize,
                        );
                        log.write_all(&buf[..accepted])?;
                        log.flush()?;
                        written += accepted as u64;
                        truncated |= accepted != count;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if status.is_none() {
                status = proc.try_wait()?;
            }
            descendants_gone =
                scope
                    .as_ref()
                    .unwrap()
                    .reap(if status.is_none() { Some(pid) } else { None })?;
            if heartbeat.elapsed() >= Duration::from_millis(100) {
                record["heartbeat"] = json!(now());
                save(&path, &record)?;
                heartbeat = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        use std::os::unix::process::ExitStatusExt;
        let status = status.unwrap();
        record["state"] = json!(reason.unwrap_or("completed"));
        record["exit_code"] = json!(status.code().unwrap_or(-status.signal().unwrap_or(1)));
        record["truncated"] = json!(truncated);
        Ok(())
    })();
    if let Some(mut proc) = child {
        if let Some(scope) = &scope {
            // Also cover errors after spawn. Do not publish a terminal record
            // until adopted children have been killed and reaped.
            loop {
                scope.signal(proc.id(), libc::SIGKILL)?;
                let _ = proc.try_wait();
                if scope.reap(None)? {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            isolation::kill_group(proc.id(), libc::SIGKILL);
            let _ = proc.wait();
        }
    }
    if let Err(error) = result {
        record["state"] = json!("failed");
        record["error"] = json!(error.message.chars().take(2000).collect::<String>());
        record["exit_code"] = Value::Null;
    }
    record["completed_at"] = json!(now());
    save(&path, &record)
}
