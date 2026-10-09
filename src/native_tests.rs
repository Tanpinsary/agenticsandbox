use crate::{config::Config, git, isolation, runtime, store::Store, transport, util::*};

use serde_json::json;
use std::{
    fs,
    os::unix::fs::symlink,
    process::{Command, Stdio},
};

#[test]
fn child_policy_cannot_widen_and_excludes_win() {
    let p = Policy::parse(&json!({"include":["src/**"],"exclude":["**/.env*"]})).unwrap();
    assert!(p.allows("src/x.rs").unwrap());
    assert!(!p.allows("src/nested/.env.local").unwrap());
    assert!(p.child(&json!({"include":["**"]})).is_err());
    assert!(
        !p.child(&json!({"include":["src/**"]}))
            .unwrap()
            .allows("src/.env")
            .unwrap()
    );
}
#[test]
fn path_access_rejects_symlink_parents_and_final_files() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"secret").unwrap();
    symlink(outside.path(), root.path().join("link")).unwrap();
    symlink(outside.path().join("secret"), root.path().join("file")).unwrap();
    for p in [
        "link/secret",
        "file",
        "../secret",
        ".git/config",
        "x/../secret",
    ] {
        assert!(safe_open(root.path(), p, libc::O_RDONLY, false, None).is_err());
    }
    assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"secret");
}
#[test]
fn hardlink_write_rejected_without_truncating_target() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("secret"), b"untouched").unwrap();
    fs::hard_link(root.path().join("secret"), root.path().join("target")).unwrap();
    let f = safe_open(root.path(), "target", libc::O_WRONLY, false, None).unwrap();
    assert!(regular(&f, true).is_err());
    assert_eq!(fs::read(root.path().join("secret")).unwrap(), b"untouched");
}
#[test]
fn unicode_case_collisions_and_forged_digests_rejected() {
    let c = Config::new(
        json!({"backend":"local","allow_unsafe_local":true,"runtimes":{"test":{}}}),
        std::path::Path::new("/tmp"),
    )
    .unwrap();
    let mut files = json!({"Straße":file_item(b"x",false),"STRASSE":file_item(b"x",false)});
    assert!(git::validate_files(&files, &c.limits).is_err());
    files = json!({"x":file_item(b"x",false)});
    files["x"]["sha256"] = json!("a".repeat(64));
    assert_eq!(
        git::validate_files(&files, &c.limits).unwrap_err().code,
        "corrupt_artifact"
    );
}
#[test]
fn remote_rejects_mutable_images_shell_hosts_and_network_expansion() {
    let settings = json!({"host":"user@host","namespace":"test-controller"});
    assert!(crate::remote::validate_config(&settings).is_ok());
    for host in [
        "-oProxyCommand=bad",
        "host;touch /tmp/canary",
        "user@host\ncommand",
        "",
    ] {
        let mut c = settings.clone();
        c["host"] = json!(host);
        assert!(crate::remote::validate_config(&c).is_err());
    }
    let p = json!({"image_digest":format!("sha256:{}","a".repeat(64)),"task_uid":10001});
    assert!(crate::remote::validate_profile(&p, "none").is_ok());
    assert!(crate::remote::validate_profile(&p, "internet").is_err());
    for image in [
        "agentic-container:latest",
        "sha256:abc",
        "agentic-container:candidate",
    ] {
        let mut p = p.clone();
        p["image_digest"] = json!(image);
        assert!(crate::remote::validate_profile(&p, "none").is_err());
    }
}
#[test]
fn remote_resolves_named_hosts_and_rejects_ambiguous_selection() {
    let multi = json!({
        "default": "lab",
        "hosts": {
            "lab": {"host": "user@lab", "namespace": "controller-a"},
            "slow": {"host": "user@slow", "namespace": "controller-b", "port": 2222}
        }
    });
    assert!(crate::remote::validate_config(&multi).is_ok());
    let by_default = crate::remote::resolve_host(&multi, &json!({})).unwrap();
    assert_eq!(by_default["name"], "lab");
    assert_eq!(by_default["host"], "user@lab");
    let by_profile = crate::remote::resolve_host(&multi, &json!({"remote_host":"slow"})).unwrap();
    assert_eq!(by_profile["name"], "slow");
    assert_eq!(by_profile["port"], 2222);
    assert!(crate::remote::resolve_host(&multi, &json!({"remote_host":"missing"})).is_err());

    // One named host needs no default or profile selection.
    let single = json!({"hosts": {"only": {"host": "user@only", "namespace": "controller-c"}}});
    assert!(crate::remote::validate_config(&single).is_ok());
    assert_eq!(
        crate::remote::resolve_host(&single, &json!({})).unwrap()["name"],
        "only"
    );

    // Several hosts with neither default nor profile selection must fail closed.
    let ambiguous = json!({"hosts": {
        "a": {"host": "user@a", "namespace": "controller-a"},
        "b": {"host": "user@b", "namespace": "controller-b"}
    }});
    assert!(crate::remote::validate_config(&ambiguous).is_ok());
    assert!(crate::remote::resolve_host(&ambiguous, &json!({})).is_err());

    for invalid in [
        json!({"hosts": {}}),
        json!({"default":"missing","hosts":{"a":{"host":"user@a","namespace":"controller-a"}}}),
        json!({"host":"user@a","namespace":"controller-a","hosts":{"a":{"host":"user@a","namespace":"controller-a"}}}),
        json!({"hosts":{"Bad Name":{"host":"user@a","namespace":"controller-a"}}}),
        json!({"hosts":{"a":{"host":"-oProxyCommand=bad","namespace":"controller-a"}}}),
        json!({"hosts":{"a":{"host":"user@a","namespace":"Bad Namespace"}}}),
    ] {
        assert!(
            crate::remote::validate_config(&invalid).is_err(),
            "expected rejection: {invalid}"
        );
    }
    // A host reference is only meaningful with a named hosts map.
    let legacy = json!({"host":"user@a","namespace":"controller-a"});
    assert!(crate::remote::resolve_host(&legacy, &json!({"remote_host":"lab"})).is_err());
    let bad_reference = json!({"image_digest":format!("sha256:{}","a".repeat(64)),"task_uid":10001,"remote_host":"Bad Name"});
    assert!(crate::remote::validate_profile(&bad_reference, "none").is_err());

    // Config::runtime must reject a runtime pointing at an unconfigured host.
    let c = Config::new(
        json!({
            "backend":"remote",
            "remote":{"hosts":{"lab":{"host":"user@lab","namespace":"controller-a"}}},
            "runtimes":{"test":{"image_digest":format!("sha256:{}","a".repeat(64)),"task_uid":10001,"remote_host":"other","networks":["none"]}},
            "networks":{"none":{}}
        }),
        std::path::Path::new("/tmp"),
    )
    .unwrap();
    assert_eq!(
        c.runtime("test", "none").unwrap_err().code,
        "unverified_runtime"
    );
}
#[test]
fn remote_rejects_tampered_container_limits_mounts_and_namespaces() {
    let v = json!({"Image":"sha256:fixed","Config":{"User":"0:0"},"HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"NetworkMode":"none","IpcMode":"private","CgroupnsMode":"private","PidMode":"","UsernsMode":"","PidsLimit":128,"Memory":4294967296u64,"MemorySwap":4294967296u64,"NanoCpus":2000000000u64,"CapDrop":["ALL"],"CapAdd":["CHOWN","SETUID","SETGID","KILL"],"SecurityOpt":["no-new-privileges:true"]},"Mounts":[{"Type":"volume","Name":"task-data","Destination":"/workspace","RW":true}]});
    assert!(crate::remote::validate_container(&v, "sha256:fixed", "task-data").is_ok());
    let mut normalized = v.clone();
    normalized["HostConfig"]["CapAdd"] =
        json!(["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_KILL"]);
    assert!(crate::remote::validate_container(&normalized, "sha256:fixed", "task-data").is_ok());
    for (k, value) in [
        ("NetworkMode", json!("host")),
        ("PidMode", json!("host")),
        ("Privileged", json!(true)),
        ("ReadonlyRootfs", json!(false)),
        ("PidsLimit", json!(0)),
        ("Memory", json!(0)),
        ("CapAdd", json!(["SYS_ADMIN"])),
        ("Binds", json!(["/:/host"])),
    ] {
        let mut changed = v.clone();
        changed["HostConfig"][k] = value;
        assert!(crate::remote::validate_container(&changed, "sha256:fixed", "task-data").is_err());
    }
    assert!(crate::remote::validate_container(&v, "sha256:other", "task-data").is_err());
    assert!(crate::remote::validate_container(&v, "sha256:fixed", "another-task-data").is_err());
}
#[test]
fn database_capabilities_and_idempotency_survive_restart() {
    let root = tempfile::tempdir().unwrap();
    private_dir(root.path()).unwrap();
    let s = Store::new(root.path()).unwrap();
    let t = s.capability("t1", now() + 60.0, &json!(["read"])).unwrap();
    s.put("task", &json!({"id":"t1","answer":42})).unwrap();
    let p = json!({"id":"admin"});
    let r = json!({"idempotency_key":"once","x":1});
    assert!(s.reserve(&p, "create", &r).unwrap().is_none());
    s.finish(&p, "create", &r, &json!({"id":"t1"})).unwrap();
    drop(s);
    let s = Store::new(root.path()).unwrap();
    assert_eq!(s.authenticate(&t).unwrap()["task_id"], "t1");
    assert_eq!(s.get("task", "t1").unwrap()["answer"], 42);
    assert_eq!(s.reserve(&p, "create", &r).unwrap().unwrap()["id"], "t1");
    assert_eq!(
        s.reserve(&p, "create", &json!({"idempotency_key":"once","x":2}))
            .unwrap_err()
            .code,
        "conflict"
    );
    s.revoke("t1").unwrap();
    assert!(s.authenticate(&t).is_err());
}
#[test]
fn transport_bounds_output_and_pipe_lifetime() {
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "printf 123456789"]).stderr(Stdio::null());
    isolation::session(&mut c);
    assert_eq!(
        transport::bounded(&mut c, &[], 5, 8).unwrap_err().code,
        "payload_too_large"
    );
    let mut c = Command::new("/bin/sh");
    c.args(["-c", "exec 1>&-; sleep 10"]).stderr(Stdio::null());
    isolation::session(&mut c);
    let start = std::time::Instant::now();
    assert!(transport::bounded(&mut c, &[], 1, 8).is_err());
    assert!(start.elapsed().as_secs() < 3);
}
#[test]
fn bidirectional_large_pipe_transport_does_not_deadlock() {
    let mut c = Command::new("cat");
    c.stderr(Stdio::null());
    isolation::session(&mut c);
    let input = vec![b'x'; 300000];
    let (code, data) = transport::bounded(&mut c, &input, 5, 300000).unwrap();
    assert_eq!(code, 0);
    assert_eq!(data, input);
}
#[test]
fn pid_gate_rejects_unlimited_missing_and_excessive_values() {
    let dir = tempfile::tempdir().unwrap();
    assert!(runtime::pid_limit(dir.path()).is_err());
    for text in ["max", "0", "129", "-1", "1.2", "999999999999999"] {
        fs::write(dir.path().join("pids.max"), text).unwrap();
        assert!(runtime::pid_limit(dir.path()).is_err());
    }
    fs::write(dir.path().join("pids.max"), "128\n").unwrap();
    assert_eq!(runtime::pid_limit(dir.path()).unwrap(), 128);
}
#[test]
fn storage_restart_marks_interrupted_process_lost_without_pid_signal() {
    let dir = tempfile::tempdir().unwrap();
    runtime::storage(dir.path(), false, Some("namespace-a")).unwrap();
    let path = crate::worker::record_path(dir.path(), "e1").unwrap();
    save(
        &path,
        &json!({"id":"e1","state":"running","pid":1,"supervisor_pid":1,"launch_pending":true}),
    )
    .unwrap();
    runtime::storage(dir.path(), false, Some("namespace-b")).unwrap();
    let r = load(&path).unwrap();
    assert_eq!(r["state"], "lost");
    assert!(r.get("pid").is_none());
    assert!(r.get("launch_pending").is_none());
}
#[test]
fn empty_files_and_deterministic_baselines_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let files = json!({"empty":file_item(b"",false)});
    let a = git::initialize(&dir.path().join("a"), &files).unwrap();
    let b = git::initialize(&dir.path().join("b"), &files).unwrap();
    assert_eq!(a, b);
    let c = Config::new(
        json!({"backend":"local","allow_unsafe_local":true,"runtimes":{"test":{}}}),
        dir.path(),
    )
    .unwrap();
    assert_eq!(
        git::export(&dir.path().join("a"), &a, &Policy::all(), &c.limits).unwrap(),
        files
    );
}

#[test]
fn batch_git_export_preserves_binary_duplicate_blobs_and_size_limits() {
    let dir = tempfile::tempdir().unwrap();
    let files = json!({"empty":file_item(b"",false), "a":file_item(b"\0\nblob\n\xff",true), "b":file_item(b"\0\nblob\n\xff",false)});
    let revision = git::initialize(dir.path(), &files).unwrap();
    let limits = json!({"max_file_bytes":8,"max_total_bytes":16,"max_files":3});
    assert_eq!(
        git::export(dir.path(), &revision, &Policy::all(), &limits).unwrap(),
        files
    );
    for (key, value) in [
        ("max_file_bytes", 7),
        ("max_total_bytes", 15),
        ("max_files", 2),
    ] {
        let mut cap = limits.clone();
        cap[key] = json!(value);
        assert!(
            git::export(dir.path(), &revision, &Policy::all(), &cap).is_err(),
            "{key}"
        );
    }
}

#[test]
fn task_git_configuration_survives_harness_environment_filtering() {
    let dir = tempfile::Builder::new()
        .prefix("task'quoted-")
        .tempdir()
        .unwrap();
    let env = isolation::environment(dir.path());
    assert!(!env.contains_key("GIT_CONFIG_COUNT"));
    let output = Command::new("git")
        .env_clear()
        .envs(env)
        .args(["config", "--get-all", "safe.directory"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        dir.path().join("repo").display().to_string()
    );
}
#[test]
fn worker_recovery_is_idempotent_and_rejects_changed_payload() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::new(
        json!({"backend":"local","allow_unsafe_local":true,"runtimes":{"test":{}}}),
        dir.path(),
    )
    .unwrap();
    let original = json!({"x":file_item(b"before",false)});
    crate::worker::dispatch(
        dir.path(),
        "install",
        &json!({"files":original,"limits":c.limits,"task_uid":null,"read_only_source":false}),
    )
    .unwrap();
    let mut req = json!({"committed_files":original,"working_files":{"x":file_item(b"dirty",false)},"limits":c.limits,"workspace_mode":"snapshot"});
    let first = crate::worker::dispatch(dir.path(), "restore", &req).unwrap();
    assert_eq!(
        first,
        crate::worker::dispatch(dir.path(), "restore", &req).unwrap()
    );
    assert_eq!(fs::read(dir.path().join("repo/x")).unwrap(), b"dirty");
    req["working_files"] = json!({});
    assert_eq!(
        crate::worker::dispatch(dir.path(), "restore", &req)
            .unwrap_err()
            .code,
        "conflict"
    );
}
