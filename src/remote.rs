use crate::{
    config::{Config, pinned_image},
    error::{Error, Result, check, ensure},
    isolation, runtime, transport,
    util::*,
    worker,
};
use serde_json::{Value, json};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"\x1eagenticsandbox-ssh-v1\x1e";
const OWNER: &str = "agenticsandbox.controller";
const TASK: &str = "agenticsandbox.task";
const STARTUP: &str = "set -eu; umask 077; agenticsandbox runtime-limits; agenticsandbox runtime-manifest verify >/dev/null; agenticsandbox runtime-storage >/dev/null; touch /run/agenticsandbox.ready; exec sleep infinity";

fn name_of(value: &str) -> bool {
    regex::Regex::new(r"^[a-z0-9][a-z0-9-]{0,39}$")
        .unwrap()
        .is_match(value)
}

fn validate_host(c: &Value) -> Result<()> {
    let host = s(c, "host");
    ensure(
        !host.starts_with('-')
            && regex::Regex::new(r"^[A-Za-z0-9_@.:-]+$")
                .unwrap()
                .is_match(&host),
        "Configure a valid SSH host or user@host",
    )?;
    ensure((1..=65535).contains(&n(c, "port", 22)), "Invalid SSH port")?;
    ensure(
        name_of(&s(c, "namespace")),
        "Configure a unique Docker namespace",
    )?;
    Ok(())
}

/// Accepts either one host block or a named `hosts` map. A named map may set
/// `default`; each runtime picks a host with `remote_host`.
pub fn validate_config(c: &Value) -> Result<()> {
    obj(c)?;
    let Some(hosts) = c.get("hosts") else {
        return validate_host(c);
    };
    ensure(
        c.get("host").is_none() && c.get("namespace").is_none(),
        "remote cannot mix a single host with named hosts",
    )?;
    let hosts = obj(hosts)?;
    ensure(!hosts.is_empty(), "Configure at least one SSH Docker host")?;
    for (name, value) in hosts {
        ensure(name_of(name), "Invalid SSH Docker host name")?;
        validate_host(value)?;
    }
    if let Some(default) = c.get("default") {
        ensure(
            default.as_str().is_some_and(|d| hosts.contains_key(d)),
            "Default SSH Docker host is not configured",
        )?;
    }
    Ok(())
}

/// Resolve the host block a runtime profile targets. A single-host config is
/// returned as-is; a named map requires `remote_host`, `default`, or
/// exactly one entry, so an ambiguous controller fails closed.
pub fn resolve_host(c: &Value, profile: &Value) -> Result<Value> {
    let wanted = profile.get("remote_host").and_then(|v| v.as_str());
    let Some(hosts) = c.get("hosts").and_then(|v| v.as_object()) else {
        ensure(
            wanted.is_none(),
            "remote_host requires a named remote hosts configuration",
        )?;
        return Ok(c.clone());
    };
    let name = match wanted {
        Some(name) => name.to_owned(),
        None => c["default"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| (hosts.len() == 1).then(|| hosts.keys().next().unwrap().clone()))
            .ok_or_else(|| {
                Error::new(
                    "Select an SSH Docker host with remote_host in the runtime profile",
                    "unverified_runtime",
                    409,
                )
            })?,
    };
    ensure(name_of(&name), "Invalid SSH Docker host reference")?;
    let mut value = hosts
        .get(&name)
        .cloned()
        .ok_or_else(|| Error::new("Unknown SSH Docker host", "unverified_runtime", 409))?;
    value["name"] = json!(name);
    Ok(value)
}

pub fn validate_profile(p: &Value, network: &str) -> Result<()> {
    let image = s(p, "image_digest");
    ensure(
        pinned_image(&image) || image.strip_prefix("sha256:").is_some_and(checksum),
        "SSH Docker requires an immutable image digest or complete local image ID",
    )?;
    ensure(
        network == "none",
        "SSH Docker currently supports network: none",
    )?;
    ensure(
        n(p, "task_uid", 10001) == 10001,
        "SSH Docker image requires task UID 10001",
    )?;
    for key in ["worker_source_sha256", "runtime_manifest_sha256"] {
        if let Some(value) = p.get(key) {
            ensure(
                checksum(value.as_str().unwrap_or("")),
                "Invalid runtime checksum",
            )?;
        }
    }
    if let Some(value) = p.get("architecture") {
        ensure(
            matches!(value.as_str(), Some("amd64" | "arm64")),
            "Invalid runtime architecture",
        )?;
    }
    if let Some(host) = p.get("remote_host") {
        ensure(
            host.as_str().is_some_and(name_of),
            "Invalid SSH Docker host reference",
        )?;
    }
    Ok(())
}

// Every argument is quoted independently; task data travels only over stdin.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub struct Remote<'a> {
    pub config: &'a Config,
    settings: Value,
}
impl<'a> Remote<'a> {
    /// Bind the backend to the host its task runtime targets.
    pub fn new(config: &'a Config, t: &Value) -> Result<Self> {
        let profile = config.runtime(&s(t, "runtime"), &s(t, "network"))?;
        Ok(Self {
            config,
            settings: resolve_host(&config.value["remote"], &profile)?,
        })
    }
    fn settings(&self) -> &Value {
        &self.settings
    }
    fn namespace(&self) -> String {
        s(self.settings(), "namespace")
    }
    fn name(&self, t: &Value) -> Result<String> {
        let id = s(t, "id");
        ensure(
            regex::Regex::new(r"^[A-Za-z0-9_-]{1,100}$")
                .unwrap()
                .is_match(&id),
            "Invalid Docker task ID",
        )?;
        Ok(format!(
            "agentic-{}-{id}-g{}",
            self.namespace(),
            n(t, "generation", 0)
        ))
    }
    fn volume(&self, t: &Value) -> Result<String> {
        Ok(format!("{}-data", self.name(t)?))
    }
    fn profile(&self, t: &Value) -> Result<Value> {
        self.config.runtime(&s(t, "runtime"), &s(t, "network"))
    }
    fn raw(&self, args: &[String], input: &[u8], seconds: u64) -> Result<(i32, Vec<u8>)> {
        let c = self.settings();
        let mut cmd = Command::new(c["ssh_cli"].as_str().unwrap_or("ssh"));
        cmd.args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
        ]);
        if b(c, "ipv4") {
            cmd.arg("-4");
        }
        cmd.args(["-p", &n(c, "port", 22).to_string()]);
        if let Some(identity) = c["identity_file"].as_str() {
            cmd.args(["-i", identity]);
        }
        let docker = c["docker_cli"].as_str().unwrap_or("/usr/bin/docker");
        let script = format!(
            "printf '\\036agenticsandbox-ssh-v1\\036'; exec {} {}",
            quote(docker),
            args.iter().map(|v| quote(v)).collect::<Vec<_>>().join(" ")
        );
        cmd.arg(s(c, "host"))
            .arg(format!("exec /bin/sh -c {}", quote(&script)))
            .stderr(Stdio::inherit());
        isolation::session(&mut cmd);
        let (code, bytes) =
            transport::bounded(&mut cmd, input, seconds, worker::MAX_REQUEST + 65536)?;
        // Some SSH login shells print a banner even with -T. The marker is
        // emitted by our command, so banners never enter the JSON protocol.
        let start = bytes
            .windows(MARKER.len())
            .position(|v| v == MARKER)
            .ok_or_else(|| {
                Error::new(
                    "SSH command did not reach Docker; check host, key and connectivity",
                    "ssh_transport",
                    503,
                )
            })?
            + MARKER.len();
        Ok((code, bytes[start..].to_vec()))
    }
    fn docker(&self, args: &[String], input: &[u8]) -> Result<Vec<u8>> {
        let (code, data) = self.raw(
            args,
            input,
            n(self.settings(), "operation_timeout_seconds", 120),
        )?;
        check(
            code == 0,
            "Remote Docker operation failed; see controller log",
            "docker_transport",
            503,
        )?;
        Ok(data)
    }
    fn simple(&self, args: &[&str]) -> Result<Vec<u8>> {
        self.docker(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &[])
    }
    fn inspect(&self, kind: &str, name: &str) -> Result<Option<Value>> {
        let (code, data) = self.raw(&[kind.into(), "inspect".into(), name.into()], &[], 30)?;
        if code == 0 {
            let values: Value = serde_json::from_slice(&data)?;
            return Ok(Some(values[0].clone()));
        }
        // A failed SSH/daemon operation must not be mistaken for absence.
        let filter = if kind == "container" {
            format!("name=^/{name}$")
        } else {
            format!("name=^{name}$")
        };
        let listed = if kind == "container" {
            self.simple(&[
                kind,
                "ls",
                "--all",
                "--filter",
                &filter,
                "--format",
                "{{.Names}}",
            ])?
        } else {
            self.simple(&[kind, "ls", "--filter", &filter, "--format", "{{.Name}}"])?
        };
        check(
            listed.is_empty(),
            "Docker resource exists but cannot be inspected",
            "docker_transport",
            503,
        )?;
        Ok(None)
    }
    fn owned(&self, labels: &Value, t: &Value) -> Result<()> {
        check(
            labels[OWNER] == self.namespace() && labels[TASK] == self.name(t)?,
            "Docker resource belongs to another controller/task",
            "unverified_runtime",
            409,
        )
    }
    pub fn verify_container(&self, value: &Value, t: &Value) -> Result<()> {
        self.owned(&value["Config"]["Labels"], t)?;
        let profile = self.profile(t)?;
        let expected = s(&profile, "image_digest");
        let image = if expected.starts_with("sha256:") {
            expected.as_bytes().to_vec()
        } else {
            self.simple(&["image", "inspect", &expected, "--format", "{{.Id}}"])?
        };
        validate_container(
            value,
            String::from_utf8_lossy(&image).trim(),
            &self.volume(t)?,
        )
    }
    pub fn call(&self, t: &Value, op: &str, req: &Value) -> Result<Value> {
        let name = self.name(t)?;
        let container = self
            .inspect("container", &name)?
            .ok_or_else(|| Error::new("Docker task container unavailable", "runtime_lost", 409))?;
        self.verify_container(&container, t)?;
        let input = canonical(&json!({"root":"/workspace","operation":op,"request":req}));
        ensure(
            input.len() as u64 <= worker::MAX_REQUEST,
            "Worker request exceeds size limit",
        )?;
        let data = self.docker(
            &[
                "exec".into(),
                "-i".into(),
                "--user".into(),
                "0:0".into(),
                name,
                "agenticsandbox".into(),
                "worker".into(),
            ],
            &input,
        )?;
        let response: Value = serde_json::from_slice(&data)?;
        if let Some(error) = response["error"].as_str() {
            return Err(Error::new(
                error,
                response["code"].as_str().unwrap_or("worker_error"),
                409,
            ));
        }
        ensure(
            response.get("result").is_some(),
            "Malformed Docker worker response",
        )?;
        Ok(response["result"].clone())
    }
    pub fn create(&self, t: &mut Value, files: &Value, bundle: Option<&[u8]>) -> Result<Value> {
        let name = self.name(t)?;
        let volume = self.volume(t)?;
        let profile = self.profile(t)?;
        let image = s(&profile, "image_digest");
        let result = (|| {
            if let Some(v) = self.inspect("volume", &volume)? {
                self.owned(&v["Labels"], t)?;
            } else {
                self.simple(&[
                    "volume",
                    "create",
                    "--label",
                    &format!("{OWNER}={}", self.namespace()),
                    "--label",
                    &format!("{TASK}={name}"),
                    &volume,
                ])?;
            }
            if self.inspect("container", &name)?.is_none() {
                self.simple(&[
                    "create",
                    "--pull=never",
                    "--name",
                    &name,
                    "--label",
                    &format!("{OWNER}={}", self.namespace()),
                    "--label",
                    &format!("{TASK}={name}"),
                    "--user",
                    "0:0",
                    "--read-only",
                    "--network",
                    "none",
                    "--ipc",
                    "private",
                    "--cgroupns",
                    "private",
                    "--memory",
                    "4g",
                    "--memory-swap",
                    "4g",
                    "--cpus",
                    "2",
                    "--pids-limit",
                    "128",
                    "--cap-drop",
                    "ALL",
                    "--cap-add",
                    "CHOWN",
                    "--cap-add",
                    "SETUID",
                    "--cap-add",
                    "SETGID",
                    "--cap-add",
                    "KILL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--ulimit",
                    "nproc=128:128",
                    "--ulimit",
                    "nofile=1024:1024",
                    "--mount",
                    &format!("type=volume,src={volume},dst=/workspace,volume-nocopy"),
                    "--tmpfs",
                    "/run:rw,nosuid,nodev,size=128m,mode=0755",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,size=128m,mode=0700",
                    "--env",
                    &format!("AGENTICSANDBOX_IMAGE_DIGEST={image}"),
                    "--entrypoint",
                    "/usr/bin/tini",
                    &image,
                    "--",
                    "/bin/sh",
                    "-c",
                    STARTUP,
                ])?;
            }
            let value = self.inspect("container", &name)?.unwrap();
            self.verify_container(&value, t)?;
            if !b(&value["State"], "Running") {
                self.simple(&["start", &name])?;
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let (code, _) = self.raw(
                    &[
                        "exec".into(),
                        name.clone(),
                        "test".into(),
                        "-f".into(),
                        "/run/agenticsandbox.ready".into(),
                    ],
                    &[],
                    10,
                )?;
                if code == 0 {
                    break;
                }
                check(
                    Instant::now() < deadline,
                    "Docker worker startup failed",
                    "runtime_startup",
                    503,
                )?;
                std::thread::sleep(Duration::from_millis(100));
            }
            runtime::validate_identity(&self.call(t, "identity", &json!({}))?, &profile)?;
            let common = json!({"limits":self.config.limits,"task_uid":10001,"read_only_source":t["role"]=="verification"});
            let mut request = common;
            let operation = if t["workspace_mode"] == "repository" {
                let bundle = bundle
                    .ok_or_else(|| Error::new("Missing input bundle", "corrupt_artifact", 409))?;
                request["bundle"] = json!(encode(bundle));
                request["base_sha"] = t["base"].clone();
                request["bundle_sha256"] = json!(digest(bundle));
                "install_repository"
            } else {
                request["files"] = files.clone();
                "install"
            };
            let mut installed = self.call(t, operation, &request)?;
            installed["handle"] = json!(name);
            installed["image_digest"] = json!(image);
            Ok(installed)
        })();
        if result.is_err() {
            t["runtime_cleanup_pending"] = json!(true);
            if self.destroy(t).is_ok() {
                t.as_object_mut().unwrap().remove("runtime_cleanup_pending");
            }
        }
        result
    }
    pub fn state(&self, t: &Value) -> Result<String> {
        match self.inspect("container", &self.name(t)?)? {
            Some(value) => {
                self.verify_container(&value, t)?;
                Ok(if b(&value["State"], "Running") {
                    "ready"
                } else {
                    "stopped"
                }
                .into())
            }
            None => Ok("lost".into()),
        }
    }
    pub fn destroy(&self, t: &Value) -> Result<()> {
        let name = self.name(t)?;
        if let Some(value) = self.inspect("container", &name)? {
            self.owned(&value["Config"]["Labels"], t)?;
            self.simple(&["rm", "--force", &name])?;
        }
        let volume = self.volume(t)?;
        if let Some(value) = self.inspect("volume", &volume)? {
            self.owned(&value["Labels"], t)?;
            self.simple(&["volume", "rm", &volume])?;
        }
        Ok(())
    }
}

pub(crate) fn validate_container(v: &Value, image_id: &str, volume: &str) -> Result<()> {
    let h = &v["HostConfig"];
    let caps: std::collections::BTreeSet<_> = strings(h.get("CapAdd").unwrap_or(&json!([])))?
        .into_iter()
        .map(|c| c.strip_prefix("CAP_").unwrap_or(&c).to_owned())
        .collect();
    let expected = ["CHOWN", "SETUID", "SETGID", "KILL"];
    let volumes: Vec<_> = v["Mounts"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter(|m| m["Type"] == "volume")
        .cloned()
        .collect();
    check(
        v["Image"] == image_id
            && v["Config"]["User"] == "0:0"
            && b(h, "ReadonlyRootfs")
            && !b(h, "Privileged")
            && h["NetworkMode"] == "none"
            && h["IpcMode"] == "private"
            && h["CgroupnsMode"] == "private"
            && h["PidMode"].as_str().unwrap_or("").is_empty()
            && h["UsernsMode"].as_str().unwrap_or("").is_empty()
            && n(h, "PidsLimit", 0) == 128
            && n(h, "Memory", 0) == 4 * 1024 * 1024 * 1024
            && n(h, "MemorySwap", 0) == 4 * 1024 * 1024 * 1024
            && n(h, "NanoCpus", 0) == 2_000_000_000
            && strings(h.get("CapDrop").unwrap_or(&json!([])))? == ["ALL"]
            && caps.len() == expected.len()
            && caps.iter().all(|c| expected.contains(&c.as_str()))
            && strings(h.get("SecurityOpt").unwrap_or(&json!([])))?
                .iter()
                .any(|s| matches!(s.as_str(), "no-new-privileges" | "no-new-privileges:true"))
            && h["Binds"].as_array().is_none_or(|a| a.is_empty())
            && h["Devices"].as_array().is_none_or(|a| a.is_empty())
            && h["DeviceRequests"].as_array().is_none_or(|a| a.is_empty())
            && h["VolumesFrom"].as_array().is_none_or(|a| a.is_empty())
            && volumes.len() == 1
            && volumes[0]["Name"] == volume
            && volumes[0]["Destination"] == "/workspace"
            && b(&volumes[0], "RW")
            && v["Mounts"].as_array().is_some_and(|a| {
                a.iter().all(|m| {
                    m["Type"] == "volume" && m["Destination"] == "/workspace"
                        || m["Type"] == "tmpfs"
                            && matches!(m["Destination"].as_str(), Some("/run" | "/tmp"))
                })
            })
            && h["PortBindings"].as_object().is_none_or(|o| o.is_empty()),
        "Docker container differs from required image, limits or isolation",
        "unverified_runtime",
        409,
    )
}
