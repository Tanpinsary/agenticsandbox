use crate::{
    error::{Error, Result, check, ensure},
    isolation,
    util::*,
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use unicode_casefold::UnicodeCaseFold;

#[derive(Clone)]
struct Context {
    root: PathBuf,
    uid: Option<u32>,
    restricted: bool,
}
thread_local! {static CONTEXT:RefCell<Option<Context>>=const{RefCell::new(None)};}
pub struct Scope(Option<Context>);
impl Scope {
    pub fn new(root: &Path, uid: Option<u32>, readonly: bool) -> Self {
        Self(CONTEXT.with(|c| {
            c.replace(Some(Context {
                root: root.into(),
                uid: if readonly { None } else { uid },
                restricted: uid.is_some(),
            }))
        }))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CONTEXT.with(|c| c.replace(self.0.take()));
    }
}

pub fn run(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    run_input(repo, args, None, false, 384 * 1024 * 1024)
}
pub fn text(repo: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&run(repo, args)?).trim().into())
}
pub fn run_input(
    repo: &Path,
    args: &[&str],
    data: Option<&[u8]>,
    deterministic: bool,
    limit: u64,
) -> Result<Vec<u8>> {
    let context = CONTEXT.with(|c| c.borrow().clone());
    // Scoped worker Git must use the installed system executable. A task's
    // writable HOME can otherwise shadow git, including root's read-only
    // verification calls. An absolute path also lets posix_spawn work with
    // the clean task PATH instead of falling back to fork's exec-error socket.
    let mut cmd = Command::new(if context.is_some() {
        "/usr/bin/git"
    } else {
        "git"
    });
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "safe.directory=*",
        "-c",
        "user.name=AgenticSandbox",
        "-c",
        "user.email=tasks@agenticsandbox.invalid",
        "-C",
    ])
    .arg(repo)
    .args(args);
    cmd.env_clear();
    if let Some(ctx) = context {
        cmd.envs(isolation::environment(&ctx.root));
        if ctx.restricted {
            isolation::restrict(&mut cmd, ctx.uid, "deny", true)?;
        } else {
            // Recovery helpers already run under the task's seccomp profile.
            // Rust's fork/pre_exec path reads an exec-error socket using recv,
            // which that profile deliberately denies. process_group preserves
            // transport cleanup while allowing libc's posix_spawn path; do not
            // relax socket or descriptor-passing restrictions for nested Git.
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
    } else {
        cmd.envs(std::env::vars().filter(|(k, _)| !k.starts_with("GIT_")));
        use std::os::unix::{fs::MetadataExt, process::CommandExt};
        if let Ok(m) = repo.metadata()
            && unsafe { libc::getuid() } == 0
            && m.uid() != 0
        {
            cmd.gid(m.uid()).uid(m.uid());
        }
        isolation::session(&mut cmd);
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1");
    if deterministic {
        for (k, v) in [
            ("GIT_AUTHOR_NAME", "AgenticSandbox"),
            ("GIT_AUTHOR_EMAIL", "tasks@agenticsandbox.invalid"),
            ("GIT_COMMITTER_NAME", "AgenticSandbox"),
            ("GIT_COMMITTER_EMAIL", "tasks@agenticsandbox.invalid"),
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z"),
        ] {
            cmd.env(k, v);
        }
    }
    cmd.stderr(Stdio::null());
    let (code, bytes) = crate::transport::bounded(&mut cmd, data.unwrap_or(&[]), 120, limit)?;
    check(code == 0, "Git operation failed", "git_error", 409)?;
    Ok(bytes)
}
pub fn resolve(repo: &Path, revision: &str) -> Result<String> {
    ensure(
        !revision.is_empty() && !revision.starts_with('-') && revision.len() <= 256,
        "Invalid Git revision",
    )?;
    let value = text(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )?;
    sha(&value)?;
    Ok(value)
}
pub fn ancestor(repo: &Path, base: &str, head: &str) -> Result<bool> {
    sha(base)?;
    sha(head)?;
    Ok(run(repo, &["merge-base", "--is-ancestor", base, head]).is_ok())
}
pub fn changes(before: &Value, after: &Value) -> Result<Vec<String>> {
    let mut keys: BTreeSet<_> = obj(before)?
        .keys()
        .chain(obj(after)?.keys())
        .cloned()
        .collect();
    keys.retain(|k| before.get(k) != after.get(k));
    Ok(keys.into_iter().collect())
}
pub fn validate_files(files: &Value, limits: &Value) -> Result<()> {
    let files = obj(files)?;
    ensure(
        files.len() as u64 <= n(limits, "max_files", 10000),
        "Too many files",
    )?;
    let mut folded = BTreeSet::new();
    let mut total = 0;
    for (path, item) in files {
        relative(path)?;
        ensure(
            folded.insert(path.case_fold().collect::<String>()),
            "Case-colliding paths",
        )?;
        ensure(
            matches!(item["mode"].as_str(), Some("100644" | "100755")),
            "Unsupported file type or mode",
        )?;
        let data = decode(&item["data"], n(limits, "max_file_bytes", 8388608))?;
        check(
            item["sha256"] == digest(&data),
            "File checksum mismatch",
            "corrupt_artifact",
            409,
        )?;
        ensure(
            !data.starts_with(b"version https://git-lfs.github.com/spec/v1\n"),
            "Git LFS is unsupported",
        )?;
        total += data.len() as u64;
        ensure(
            total <= n(limits, "max_total_bytes", 67108864),
            "Snapshot exceeds total size",
        )?;
        let parts: Vec<_> = path.split('/').collect();
        for i in 1..parts.len() {
            ensure(
                !files.contains_key(&parts[..i].join("/")),
                "Conflicting file paths",
            )?;
        }
    }
    Ok(())
}
pub fn export(repo: &Path, revision: &str, policy: &Policy, limits: &Value) -> Result<Value> {
    sha(revision)?;
    let entries = run(repo, &["ls-tree", "-rz", "--full-tree", revision])?;
    let mut files = json!({});
    let mut selected = Vec::new();
    let mut query = Vec::new();
    let mut total = 0;
    for entry in entries.split(|c| *c == 0).filter(|s| !s.is_empty()) {
        let Some(index) = entry.iter().position(|c| *c == b'\t') else {
            return Err(Error::new("Invalid Git tree", "git_error", 409));
        };
        let path = std::str::from_utf8(&entry[index + 1..])
            .map_err(|_| Error::new("Non UTF-8 paths unsupported", "invalid_request", 400))?;
        relative(path)?;
        if !policy.allows(path)? {
            continue;
        }
        let metadata = std::str::from_utf8(&entry[..index])
            .map_err(|_| Error::new("Invalid Git tree", "git_error", 409))?;
        let fields: Vec<_> = metadata.split_whitespace().collect();
        ensure(
            fields.len() == 3 && matches!(fields[0], "100644" | "100755") && fields[1] == "blob",
            "Unsupported file type",
        )?;
        ensure(
            (selected.len() as u64) < n(limits, "max_files", 10000),
            "Too many files",
        )?;
        ensure(
            fields[2].bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid object ID",
        )?;
        query.extend_from_slice(fields[2].as_bytes());
        query.push(b'\n');
        selected.push((path.to_owned(), fields[0].to_owned(), fields[2].to_owned()));
    }
    if selected.is_empty() {
        return Ok(files);
    }
    // Validate all sizes before requesting any blob data. Two bounded Git
    // processes replace two processes per file, including binary/empty blobs.
    let sizes = run_input(
        repo,
        &["cat-file", "--batch-check"],
        Some(&query),
        false,
        selected.len() as u64 * 128,
    )?;
    let lines: Vec<_> = sizes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    ensure(
        lines.len() == selected.len(),
        "Incomplete Git size response",
    )?;
    let mut validated = Vec::new();
    for ((path, mode, oid), line) in selected.into_iter().zip(lines) {
        let line = std::str::from_utf8(line)
            .map_err(|_| Error::new("Invalid Git size response", "git_error", 409))?;
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure(
            fields.len() == 3 && fields[0] == oid && fields[1] == "blob",
            "Invalid Git object response",
        )?;
        let size = fields[2]
            .parse::<u64>()
            .map_err(|_| Error::new("Invalid object size", "git_error", 409))?;
        ensure(
            size <= n(limits, "max_file_bytes", 8388608),
            "File too large",
        )?;
        total += size;
        ensure(
            total <= n(limits, "max_total_bytes", 67108864),
            "Snapshot too large",
        )?;
        validated.push((path, mode, oid, size));
    }
    let data = run_input(
        repo,
        &["cat-file", "--batch"],
        Some(&query),
        false,
        total + validated.len() as u64 * 128,
    )?;
    let mut remainder = data.as_slice();
    for (path, mode, oid, size) in validated {
        let end = remainder
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| Error::new("Incomplete Git blob header", "git_error", 409))?;
        ensure(end <= 128, "Git blob header too large")?;
        let expected = format!("{oid} blob {size}");
        ensure(
            &remainder[..end] == expected.as_bytes(),
            "Git blob response mismatch",
        )?;
        remainder = &remainder[end + 1..];
        let size = size as usize;
        ensure(
            remainder.len() > size && remainder[size] == b'\n',
            "Incomplete Git blob",
        )?;
        files[path] = file_item(&remainder[..size], mode == "100755");
        remainder = &remainder[size + 1..];
    }
    ensure(remainder.is_empty(), "Unexpected Git blob data")?;
    validate_files(&files, limits)?;
    Ok(files)
}
pub fn write_files(repo: &Path, files: &Value) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    for (path, item) in obj(files)? {
        let mut f = safe_open(
            repo,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK,
            true,
            None,
        )?;
        regular(&f, true)?;
        f.set_len(0)?;
        f.write_all(&decode(&item["data"], u64::MAX / 8)?)?;
        f.set_permissions(fs::Permissions::from_mode(if item["mode"] == "100755" {
            0o755
        } else {
            0o644
        }))?;
    }
    Ok(())
}
pub fn update_index(repo: &Path, before: &Value, after: &Value) -> Result<()> {
    let changed = changes(before, after)?;
    for path in &changed {
        if after.get(path).is_none() {
            run(repo, &["update-index", "--force-remove", "--", path])?;
        }
    }
    for path in &changed {
        if let Some(item) = after.get(path) {
            let oid = String::from_utf8_lossy(&run_input(
                repo,
                &["hash-object", "-w", "--stdin"],
                Some(&decode(&item["data"], u64::MAX / 8)?),
                false,
                1024,
            )?)
            .trim()
            .to_owned();
            run(
                repo,
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &s(item, "mode"),
                    &oid,
                    path,
                ],
            )?;
        }
    }
    Ok(())
}
pub fn commit(
    repo: &Path,
    tree: &str,
    parents: &[&str],
    message: &str,
    deterministic: bool,
) -> Result<String> {
    let mut args = vec!["commit-tree", tree];
    for p in parents {
        sha(p)?;
        args.extend(["-p", p]);
    }
    let bytes = run_input(repo, &args, Some(message.as_bytes()), deterministic, 1024)?;
    let result = String::from_utf8_lossy(&bytes).trim().to_owned();
    sha(&result)?;
    Ok(result)
}
pub fn initialize(repo: &Path, files: &Value) -> Result<String> {
    fs::create_dir_all(repo)?;
    ensure(
        !repo.join(".git").exists(),
        "Repository already initialized",
    )?;
    run(repo, &["init", "--template=", "-b", "task"])?;
    write_files(repo, files)?;
    update_index(repo, &json!({}), files)?;
    let tree = text(repo, &["write-tree"])?;
    let head = commit(repo, &tree, &[], "AgenticSandbox task baseline\n", true)?;
    run(repo, &["update-ref", "refs/heads/task", &head])?;
    run(repo, &["reset", "--hard", &head])?;
    Ok(head)
}
pub fn patch(directory: &Path, before: &Value, after: &Value) -> Result<Vec<u8>> {
    let base = initialize(directory, before)?;
    update_index(directory, before, after)?;
    let tree = text(directory, &["write-tree"])?;
    let head = commit(directory, &tree, &[&base], "Frozen task result\n", true)?;
    run(
        directory,
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            &base,
            &head,
        ],
    )
}
pub fn clone_base(source: &Path, dest: &Path, head: &str) -> Result<()> {
    fs::create_dir_all(dest.parent().unwrap())?;
    run(
        dest.parent().unwrap(),
        &[
            "clone",
            "--no-local",
            "--no-checkout",
            "--no-tags",
            "--template=",
            &source.display().to_string(),
            &dest.display().to_string(),
        ],
    )?;
    run(dest, &["checkout", "--detach", sha(head)?])?;
    run(dest, &["remote", "remove", "origin"])?;
    ensure(
        !dest.join(".git/objects/info/alternates").exists(),
        "External object store forbidden",
    )
}
pub fn bundle(source: &Path, head: &str, limits: &Value) -> Result<Vec<u8>> {
    let temp = tempfile::tempdir()?;
    let dest = temp.path().join("repo");
    clone_base(source, &dest, head)?;
    let path = temp.path().join("input.bundle");
    run(
        &dest,
        &["update-ref", "refs/heads/agenticsandbox/base", head],
    )?;
    run(
        &dest,
        &[
            "bundle",
            "create",
            &path.display().to_string(),
            "refs/heads/agenticsandbox/base",
        ],
    )?;
    read_limit(
        fs::File::open(path)?,
        n(limits, "max_bundle_bytes", 67108864),
    )
}
pub fn linear(repo: &Path, base: &str, head: &str) -> Result<Vec<String>> {
    check(
        ancestor(repo, base, head)?,
        "History no longer contains baseline",
        "history_rewritten",
        409,
    )?;
    let lines = text(
        repo,
        &[
            "rev-list",
            "--reverse",
            "--parents",
            "--max-count=101",
            head,
            &format!("^{base}"),
        ],
    )?;
    let mut previous = base.to_owned();
    let mut commits = Vec::new();
    for line in lines.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        check(
            fields.len() == 2 && fields[1] == previous && commits.len() < 100,
            "Results require at most 100 linear commits",
            "unsupported_history",
            409,
        )?;
        sha(fields[0])?;
        previous = fields[0].into();
        commits.push(previous.clone());
    }
    check(
        previous == head,
        "Incomplete commit chain",
        "corrupt_artifact",
        409,
    )?;
    Ok(commits)
}
pub fn result_bundle(
    repo: &Path,
    base: &str,
    head: &str,
    limits: &Value,
) -> Result<Option<Vec<u8>>> {
    if linear(repo, base, head)?.is_empty() {
        return Ok(None);
    }
    let name = format!("refs/agenticsandbox/results/{head}");
    run(repo, &["update-ref", &name, head])?;
    let result = run_input(
        repo,
        &["bundle", "create", "-", &name, &format!("^{base}")],
        None,
        false,
        n(limits, "max_bundle_bytes", 67108864),
    );
    let _ = run(repo, &["update-ref", "-d", &name, head]);
    result.map(Some)
}
#[allow(clippy::too_many_arguments)] // The independent receiver validates every frozen bundle field.
pub fn receive(
    repo: &Path,
    base: &str,
    head: &str,
    bundle: Option<&[u8]>,
    sum: &Value,
    policy: &Policy,
    files: &Value,
    limits: &Value,
) -> Result<Vec<String>> {
    sha(base)?;
    sha(head)?;
    if head == base {
        check(
            bundle.is_none() && sum.is_null(),
            "Unexpected result bundle",
            "corrupt_artifact",
            409,
        )?;
    } else {
        let bytes =
            bundle.ok_or_else(|| Error::new("Missing result bundle", "corrupt_artifact", 409))?;
        check(
            bytes.len() as u64 <= n(limits, "max_bundle_bytes", 67108864) && sum == &digest(bytes),
            "Result bundle checksum mismatch",
            "corrupt_artifact",
            409,
        )?;
        let end = bytes
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or_else(|| Error::new("Invalid bundle header", "corrupt_artifact", 409))?;
        let header = std::str::from_utf8(&bytes[..end])
            .map_err(|_| Error::new("Invalid bundle header", "corrupt_artifact", 409))?;
        let mut lines = header.lines();
        check(
            matches!(lines.next(), Some("# v2 git bundle" | "# v3 git bundle")),
            "Invalid bundle header",
            "corrupt_artifact",
            409,
        )?;
        let prerequisites: Vec<_> = lines
            .filter_map(|s| {
                s.strip_prefix('-')
                    .and_then(|s| s.split_whitespace().next())
            })
            .collect();
        check(
            prerequisites == [base],
            "Bundle must depend only on baseline",
            "corrupt_artifact",
            409,
        )?;
        // An already restricted recovery helper cannot write /workspace,
        // which remains controller-owned. Its task tmp directory is writable.
        // Controller-side receivers keep using their private parent directory.
        let temp_root = CONTEXT.with(|c| {
            c.borrow()
                .as_ref()
                .filter(|ctx| !ctx.restricted)
                .map(|ctx| ctx.root.join("tmp"))
                .unwrap_or_else(|| repo.parent().unwrap().to_path_buf())
        });
        let temp = tempfile::tempdir_in(temp_root)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755))?;
        let path = temp.path().join("result.bundle");
        atomic(&path, bytes, 0o644)?;
        let path = path.display().to_string();
        let name = format!("refs/agenticsandbox/results/{head}");
        run(repo, &["bundle", "verify", &path])?;
        check(
            text(repo, &["bundle", "list-heads", &path])? == format!("{head} {name}"),
            "Bundle does not match frozen commit",
            "corrupt_artifact",
            409,
        )?;
        run(
            repo,
            &[
                "-c",
                "fetch.fsckObjects=true",
                "-c",
                "transfer.fsckObjects=true",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                &path,
                &format!("{name}:refs/agenticsandbox/received"),
            ],
        )?;
    }
    let commits = linear(repo, base, head)?;
    let mut before = export(repo, base, &Policy::all(), limits)?;
    let mut total = 0;
    for revision in &commits {
        let size = text(repo, &["cat-file", "-s", revision])?
            .parse::<u64>()
            .unwrap_or(u64::MAX);
        total += size;
        ensure(
            size <= 100000 && total <= 1048576,
            "Commit metadata too large",
        )?;
        let after = export(repo, revision, &Policy::all(), limits)?;
        for path in changes(&before, &after)? {
            check(
                policy.allows(&path)?,
                "Commit modifies unauthorized path",
                "forbidden",
                403,
            )?;
        }
        before = after;
    }
    check(
        &before == files,
        "Bundle tree differs from frozen files",
        "corrupt_artifact",
        409,
    )?;
    Ok(commits)
}
