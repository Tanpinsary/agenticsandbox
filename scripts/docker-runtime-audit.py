"""Exercise the candidate image on Docker; never connects to Coder or approves a template."""
import argparse
import json
import re
import subprocess
import time
import uuid
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from support.native import LIMITS, WORKER_PROTOCOL_VERSION
from support.json_helpers import atomic_write, canonical, decode, digest, encode

def source_sha256():
    root = Path(__file__).resolve().parents[1]
    paths = [*sorted((root / "src").rglob("*.rs")), root / "src/tools.json",
             root / "Cargo.toml", root / "Cargo.lock", root / "build.rs"]
    return digest(canonical({p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in paths}))


class DockerAudit:
    def __init__(self, image, context=None, pids_limit=128):
        self.image = image
        self.command = ["docker"] + (["--context", context] if context else [])
        self.pids_limit = pids_limit
        self.run_id = uuid.uuid4().hex
        self.containers = []
        self.volumes = {}
        self.checks = {}
        self.limits = dict(LIMITS)

    def docker(self, *args, payload=None):
        result = subprocess.run(self.command + list(args), input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        if result.returncode:
            # Do not include bootstrap, environment or task contents in errors.
            raise RuntimeError("Docker audit operation failed: " + args[0])
        return result.stdout

    def create(self, role):
        name = "agenticsandbox-audit-" + self.run_id + "-" + role
        if name not in self.containers:
            self.containers.append(name)
        volume = self.volumes.get(name)
        if volume is None:
            volume = "agentic-audit-" + self.run_id + "-" + role
            self.docker("volume", "create", "--label", "agenticsandbox.audit=" + self.run_id, volume)
            self.volumes[name] = volume
        self.docker("create", "--pull=never", "--name", name,
            "--label", "agenticsandbox.audit=" + self.run_id,
            "--user", "0:0", "--read-only", "--network", "bridge", "--ipc", "private",
            "--cgroupns", "private", "--memory", "4g", "--memory-swap", "4g", "--cpuset-cpus", "0-1",
            "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
            "--cap-add", "KILL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.pids_limit),
            "--ulimit", "nproc=128:128", "--ulimit", "nofile=1024:1024",
            "--mount", "type=volume,src=" + volume + ",dst=/workspace,volume-nocopy",
            "--tmpfs", "/run:rw,nosuid,nodev,size=128m,mode=0755",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=0700",
            "--env", "CODER_AGENT_TOKEN=synthetic-audit-token",
            "--env", "CODER_INIT_SCRIPT=exec sleep infinity",
            "--env", "AGENTICSANDBOX_IMAGE_DIGEST=" + self.image,
            self.image)
        # The Docker provider cannot express pids_limit; mirror the explicit
        # per-container value that Terraform's host-side hook applies before
        # opening the entrypoint gate.
        self.docker("start", name)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            inspected = json.loads(self.docker("inspect", name))[0]
            if not inspected["State"]["Running"]:
                raise RuntimeError("Audit container refused startup; check the explicit PID limit and image")
            ready = self.docker("exec", name, "python3", "-c",
                "from pathlib import Path; print(Path('/run/coder/init.sh').is_file())").strip()
            if ready == b"True":
                return name
            time.sleep(.1)
        raise RuntimeError("Audit container startup timed out")

    def worker(self, name, operation, request):
        # docker exec may otherwise use a more permissive umask than the real
        # Coder bootstrap. Exercise installations/restores under umask 077.
        response = json.loads(self.docker("exec", "-i", name, "agenticsandbox", "worker",
            payload=canonical({"root": "/workspace", "operation": operation, "request": request})))
        if "error" in response:
            raise RuntimeError("Worker audit operation failed: " + operation)
        return response["result"]

    def install(self, name, role, read_only=False):
        content = ("audit_role = " + repr(role) + "\n").encode()
        return self.worker(name, "install", {"files": {role + ".py": {
            "mode": "100644", "data": encode(content), "sha256": digest(content)}},
            "limits": self.limits, "task_uid": 10001, "read_only_source": read_only})

    def start(self, name, argv, timeout=20):
        identifier = "e" + uuid.uuid4().hex
        self.worker(name, "start", {"id": identifier, "argv": argv, "cwd": None, "work_dir": "repo",
            "timeout_seconds": timeout, "max_output_bytes": 65536, "task_uid": 10001, "network_mode": "deny"})
        return identifier

    def result(self, name, identifier):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            record = self.worker(name, "execution", {"id": identifier})
            if record["state"] not in ("starting", "running"):
                if record["state"] != "completed" or record.get("exit_code") != 0:
                    raise RuntimeError("Restricted audit command failed")
                logs = self.worker(name, "logs", {"id": identifier, "cursor": 0})
                return decode(logs["data"])
            time.sleep(.1)
        raise RuntimeError("Restricted audit command timed out")

    def run(self):
        image = json.loads(self.docker("image", "inspect", self.image))[0]
        checks = self.checks
        namespaces = []
        names = [self.create(role) for role in ("a", "b", "verification")]
        runtime_identities = [self.worker(name, "identity", {}) for name in names]
        checks["worker_build_manifest"] = all(value.get("runtime_manifest_verified") is True
            and value.get("worker_protocol_version") == WORKER_PROTOCOL_VERSION
            and value.get("implementation") == "rust"
            and value.get("worker_source_sha256") == source_sha256() for value in runtime_identities)
        baselines = [self.install(name, role, read_only=role == "verification")
                     for name, role in zip(names, ("a", "b", "verification"))]
        for name in names:
            inspected = json.loads(self.docker("inspect", name))[0]
            host = inspected["HostConfig"]
            checks[name + "/host_configuration"] = (
                inspected["Image"] == image["Id"] and host["ReadonlyRootfs"] and not host["Privileged"]
                and not host.get("Binds") and not any(m["Type"] == "bind" for m in inspected["Mounts"])
                and [(m["Name"], m["Destination"], m["RW"]) for m in inspected["Mounts"] if m["Type"] == "volume"]
                    == [(self.volumes[name], "/workspace", True)]
                and host["NetworkMode"] == "bridge" and host["IpcMode"] == "private"
                and host.get("PidMode", "") == "" and host["CgroupnsMode"] == "private"
                and host.get("PidsLimit") == self.pids_limit
                and host["Memory"] == 4 * 1024**3)
            namespaces.append(json.loads(self.docker("exec", name, "python3", "-c",
                "import json,os; print(json.dumps({n:os.readlink('/proc/self/ns/'+n) for n in ('pid','mnt','ipc','net','cgroup')}))")))
            mandatory = self.docker("exec", name, "python3", "-c",
                "from pathlib import Path; print(all(p.is_file() and p.stat().st_uid == 0 "
                "for p in (Path('/run/coder/init.sh'), Path('/workspace/control/install.json'))))")
            checks[name + "/control_files_present"] = mandatory.strip() == b"True"
            output = self.result(name, self.start(name, ["agenticsandbox", "probe"]))
            checks[name + "/task_probe"] = json.loads(output).get("passed") is True
        checks["distinct_namespaces"] = all(len({item[key] for item in namespaces}) == len(names)
                                            for key in namespaces[0])
        for name, other in ((names[0], "b"), (names[1], "a")):
            code = ("from pathlib import Path; import subprocess; "
                f"missing=not Path({other + '.py'!r}).exists(); "
                "history=subprocess.check_output(['git','log','--all','-p']); "
                f"raise SystemExit(0 if missing and {('audit_role = ' + repr(other))!r}.encode() not in history else 1)")
            self.result(name, self.start(name, ["python3", "-c", code]))
        checks["other_task_code_and_history_absent"] = True
        marker = ("other-task-process-" + uuid.uuid4().hex).encode()
        process_id = self.start(names[1], ["python3", "-c", "import time; time.sleep(90)", marker.decode()], timeout=120)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            record = self.worker(names[1], "execution", {"id": process_id})
            if record["state"] == "running":
                break
            if record["state"] != "starting":
                raise RuntimeError("Other-task process fixture could not start")
            time.sleep(.1)
        else:
            raise RuntimeError("Other-task process fixture timed out")
        visible_in_b = self.docker("exec", "-i", names[1], "python3", "-c",
            "import sys; from pathlib import Path; "
            f"print(sys.stdin.buffer.read() in Path('/proc/{record['pid']}/cmdline').read_bytes())", payload=marker)
        if visible_in_b.strip() != b"True":
            raise RuntimeError("Other-task process marker was not present in its own namespace")
        # Store the marker as data so A's own argv does not contain the needle.
        self.docker("exec", "-i", "--user", "10001:10001", names[0], "python3", "-c",
            "import sys; from pathlib import Path; p=Path('/workspace/tmp/other-process-marker'); "
            "p.write_bytes(sys.stdin.buffer.read()); p.chmod(0o644)", payload=marker)
        process_check = """from pathlib import Path
needle = Path('/workspace/tmp/other-process-marker').read_bytes()
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        data = path.read_bytes()
    except OSError:
        continue
    if needle in data:
        raise SystemExit(1)
"""
        self.result(names[0], self.start(names[0], ["python3", "-c", process_check]))
        if self.worker(names[1], "execution", {"id": process_id})["state"] != "running":
            raise RuntimeError("Other-task process stopped before the visibility test finished")
        checks["live_other_task_process_not_visible"] = True
        verify_code = """from pathlib import Path
import subprocess
for path in (Path('verification.py'), Path('new-source.py'), Path('.git/audit-write')):
    try:
        with path.open('ab') as stream:
            stream.write(b'audit')
    except PermissionError:
        continue
    raise SystemExit(1)
subprocess.run(['git', 'log', '-1'], check=True, stdout=subprocess.DEVNULL)
Path('/workspace/build/output.txt').write_text('build output')
"""
        self.result(names[2], self.start(names[2], ["python3", "-c", verify_code]))
        checks["verification_source_read_only_git_readable_build_writable"] = True
        # Task-installed tools must not replace controller-side Git, especially
        # when root reads a verification repository owned by the controller.
        shadow_git = """from pathlib import Path
directory = Path('/workspace/home/.local/bin')
directory.mkdir(parents=True, exist_ok=True)
directory.parent.chmod(0o755)
directory.chmod(0o755)
path = directory / 'git'
path.write_text('#!/bin/sh\\nexit 97\\n')
path.chmod(0o755)
"""
        self.result(names[2], self.start(names[2], ["python3", "-c", shadow_git]))
        verified = self.worker(names[2], "export", {"baseline_sha": baselines[2]["baseline_sha"],
            "workspace_mode": "snapshot", "limits": self.limits})
        checks["task_home_cannot_shadow_worker_git"] = verified["sha"] == baselines[2]["baseline_sha"]
        self.result(names[2], self.start(names[2], ["python3", "-c",
            "from pathlib import Path; Path('/workspace/home/.local/bin/git').unlink()"]))
        implementation = self.start(names[0], ["python3", "-c",
            "from pathlib import Path; import subprocess; Path('result.bin').write_bytes(bytes(range(256))); "
            "subprocess.run(['git','add','--all'],check=True); subprocess.run(['git','commit','-m','audit result'],check=True)"])
        self.result(names[0], implementation)
        exported = self.worker(names[0], "export", {"baseline_sha": baselines[0]["baseline_sha"],
            "workspace_mode": "snapshot", "limits": self.limits})
        checks["implementation_git_and_binary_export"] = decode(exported["files"]["result.bin"]["data"]) == bytes(range(256))
        self.check_persistence(names[0], baselines[0], exported["sha"])
        self.check_restores(names[0], baselines[0])
        return {"image_id": image["Id"], "runtime_identity": runtime_identities[0], "checks": checks, "passed": all(checks.values())}

    def check_restores(self, source, baseline):
        # Exercise writable recovery without DAC_OVERRIDE/FOWNER, including
        # a committed file becoming a directory in the dirty working tree.
        self.result(source, self.start(source, ["python3", "-c",
            "from pathlib import Path; p=Path('result.bin'); p.unlink(); p.mkdir(); "
            "(p/'dirty.txt').write_text('restored dirty tree')"]))
        cp = self.worker(source, "checkpoint", {"baseline_sha": baseline["baseline_sha"],
            "workspace_mode": "snapshot", "files": {"include": ["**"]}, "limits": self.limits})
        target = self.create("restore")
        self.install(target, "a")
        request = {"workspace_mode": "snapshot", "committed_files": cp["files"],
                   "working_files": cp["working_files"], "limits": self.limits}
        restored = self.worker(target, "restore", request)
        self.checks["snapshot_restore_idempotent"] = self.worker(target, "restore", request) == restored
        private_file = "result.bin/dirty.txt"
        self.checks["private_task_file_read"] = decode(self.worker(target, "read", {"path":private_file})["data"]) == b"restored dirty tree"
        self.worker(target, "write", {"path":private_file, "data":encode(b"updated private file")})
        self.result(target, self.start(target, ["python3", "-c",
            "import os,subprocess; from pathlib import Path; "
            "assert Path('result.bin/dirty.txt').read_text() == 'updated private file'; "
            "assert Path('result.bin').stat().st_uid == os.getuid() == 10001; "
            "assert subprocess.check_output(['git','show','HEAD:result.bin']) == bytes(range(256)); "
            "Path('result.bin/after.txt').write_text('writable')"]))
        self.checks["snapshot_restore_task_ownership_and_dirty_transition"] = True
        # A full repository recovery must retain original commit IDs as well.
        self.result(source, self.start(source, ["git", "bundle", "create", "/workspace/build/input.bundle", "HEAD"]))
        bundle = self.docker("exec", "--user", "10001:10001", source, "cat", "/workspace/build/input.bundle")
        base = cp["sha"]
        repo_request = {"bundle": encode(bundle), "bundle_sha256": digest(bundle), "base_sha": base,
                        "limits": self.limits, "task_uid": 10001, "read_only_source": False}
        repository = self.create("repository")
        self.worker(repository, "install_repository", repo_request)
        self.result(repository, self.start(repository, ["python3", "-c",
            "from pathlib import Path; import subprocess; Path('committed.txt').write_text('commit'); "
            "subprocess.run(['git','add','--all'],check=True); subprocess.run(['git','commit','-m','recovery fixture'],check=True); "
            "Path('dirty.txt').write_text('dirty')"]))
        history = self.worker(repository, "checkpoint", {"baseline_sha": base,
            "workspace_mode": "repository", "limits": self.limits})
        receiver = self.create("repository-restore")
        self.worker(receiver, "install_repository", repo_request)
        recovery = {"workspace_mode": "repository", "base_sha": base, "sha": history["sha"],
                    "bundle": history["bundle"], "bundle_sha256": history["bundle_sha256"],
                    "files": {"include": ["**"]}, "committed_files": history["files"],
                    "working_files": history["working_files"], "limits": self.limits}
        self.worker(receiver, "restore", recovery)
        self.result(receiver, self.start(receiver, ["python3", "-c",
            "from pathlib import Path; import subprocess; "
            "assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip() == " + repr(history["sha"]) + "; "
            "assert Path('committed.txt').read_text() == 'commit'; assert Path('dirty.txt').read_text() == 'dirty'; "
            "Path('dirty.txt').write_text('writable')"]))
        self.checks["repository_restore_commit_ids_and_dirty_files"] = True

    def check_persistence(self, name, baseline, committed_sha):
        tool_check = """import json, subprocess
from pathlib import Path
versions = {}
for name in ('node', 'npm'):
    versions[name] = subprocess.check_output([name, '--version'], text=True).strip()
assert not Path('/opt/agents').exists()
assert all(not Path('/usr/local/bin', name).exists() for name in ('codex', 'claude', 'dsh'))
Path('/workspace/home/.codex').mkdir(exist_ok=True)
Path('/workspace/home/.codex/session-fixture').write_text('synthetic session')
Path('/workspace/home/.dsh').mkdir(exist_ok=True)
Path('/workspace/home/.dsh/session-fixture').write_text('synthetic session')
Path('/workspace/home/.claude').mkdir(exist_ok=True)
Path('/workspace/home/.claude/session-fixture').write_text('synthetic session')
Path('uncommitted.txt').write_text('uncommitted changes')
package=Path('/workspace/build/npm-fixture')
package.mkdir(exist_ok=True)
(package/'package.json').write_text(json.dumps({'name':'agentic-offline-fixture','version':'1.0.0','bin':{'agentic-fixture':'bin.js'}}))
(package/'bin.js').write_text('#!/usr/bin/env node\\nconsole.log("persistent npm install")\\n')
(package/'bin.js').chmod(0o755)
subprocess.run(['npm','install','--global','--offline','--ignore-scripts','--no-audit','--no-fund',str(package)],check=True,stdout=subprocess.DEVNULL)
print(json.dumps(versions))
"""
        output = self.result(name, self.start(name, ["python3", "-c", tool_check]))
        versions = json.loads(output.decode().splitlines()[-1])
        self.checks["base_tools_without_preinstalled_harnesses"] = all(versions.values())
        running = self.start(name, ["python3", "-c",
            "from pathlib import Path; import time; "
            "p=Path('/workspace/build/launch-count'); p.write_text(str(int(p.read_text())+1) if p.exists() else '1'); "
            "time.sleep(90)"], timeout=120)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            record = self.worker(name, "execution", {"id": running})
            ready = self.docker("exec", name, "python3", "-c",
                "from pathlib import Path; print(Path('/workspace/build/launch-count').is_file())").strip()
            if record["state"] == "running" and ready == b"True":
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Persistence interruption fixture did not start")
        # Mirror Coder stop/start: delete the container, keep its named volume,
        # create a different container from the exact same immutable image.
        old_id = json.loads(self.docker("inspect", name))[0]["Id"]
        self.docker("rm", "--force", name)
        if self.create("a") != name:
            raise RuntimeError("Persistence fixture name mismatch")
        new_id = json.loads(self.docker("inspect", name))[0]["Id"]
        self.checks["container_recreated_with_same_volume"] = old_id != new_id
        self.checks["install_retry_preserves_workspace"] = self.install(name, "a") == baseline
        check = """import subprocess
from pathlib import Path
assert Path('uncommitted.txt').read_text() == 'uncommitted changes'
assert Path('result.bin').read_bytes() == bytes(range(256))
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip() == COMMITTED_SHA
for agent in ('.codex','.claude','.dsh'):
    assert Path('/workspace/home',agent,'session-fixture').read_text() == 'synthetic session'
assert Path('/workspace/build/launch-count').read_text() == '1'
assert subprocess.check_output(['agentic-fixture'],text=True).strip() == 'persistent npm install'
""".replace("COMMITTED_SHA", repr(committed_sha))
        self.result(name, self.start(name, ["python3", "-c", check]))
        self.checks["git_dirty_files_home_dependencies_preserved"] = True
        self.checks["interrupted_execution_lost_without_replay"] = self.worker(name, "execution", {"id": running})["state"] == "lost"
        self.result(name, self.start(name, ["agenticsandbox", "probe"]))
        self.checks["task_isolation_after_recreation"] = True

    def cleanup(self):
        complete = True
        for name in reversed(self.containers):
            try:
                container = json.loads(self.docker("inspect", name))[0]
                if container["Config"]["Labels"].get("agenticsandbox.audit") == self.run_id:
                    self.docker("rm", "--force", name)
            except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
                complete = False
        for volume in self.volumes.values():
            try:
                inspected = json.loads(self.docker("volume", "inspect", volume))[0]
                if inspected.get("Labels", {}).get("agenticsandbox.audit") == self.run_id:
                    self.docker("volume", "rm", volume)
            except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
                complete = False
        return complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Existing registry digest or full local sha256 image ID")
    parser.add_argument("--context", help="Existing Docker context; no daemon settings are changed")
    parser.add_argument("--pids-limit", type=int, default=128,
                        help="Per-container PID limit used by the audit (default: 128)")
    parser.add_argument("--output", type=Path, required=True, help="JSON evidence file outside the containers")
    args = parser.parse_args()
    if not re.fullmatch(r"(?:[^\s@]+@)?sha256:[0-9a-f]{64}", args.image):
        parser.error("image must be immutable; mutable tags are not accepted")
    if not 1 <= args.pids_limit <= 128:
        parser.error("--pids-limit must be between 1 and 128")
    audit = DockerAudit(args.image, args.context, args.pids_limit)
    report = {"scope": "agentic_container_persistent_volume_none_network", "production_approved": False,
        "real_coder_credentials_tested": False, "image": args.image,
        "pids_limit": args.pids_limit, "passed": False}
    try:
        report.update(audit.run())
    except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
        report["error"] = str(exc) if isinstance(exc, RuntimeError) else "Docker audit could not finish"
    finally:
        report["checks"] = audit.checks
        report["cleanup_complete"] = audit.cleanup()
    report["passed"] = report["passed"] and report["cleanup_complete"]
    data = canonical(report)
    atomic_write(args.output, data)
    print(json.dumps({"passed": report["passed"], "production_approved": False,
                      "report": str(args.output), "sha256": digest(data)}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
