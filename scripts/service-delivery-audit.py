"""Run full Service delivery on a synthetic repository using an approved runtime.

Never edits registered repositories or grants runtime approval. --local is a
protocol fixture; real Coder mode requires an existing approved configuration.
"""
import argparse
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from support import git as gitops, native
from support.native import FixtureConfig, NativeClient, WORKER_PROTOCOL_VERSION
from support.json_helpers import SandboxError, atomic_write, canonical, decode, digest


class DeliveryAudit:
    def __init__(self, config, runtime, mode, directory):
        # State and the only repository are new and synthetic. Keep the input
        # config's credential/runtime settings; do not copy its state or repos.
        value = dict(config.value)
        self.source = directory / "project"
        value.update(state_dir=str(directory / "state"), admin_token_file=str(directory / "admin.token"),
                     repos={"synthetic": str(self.source)}, agents={})
        self.config = FixtureConfig(value)
        self.runtime, self.mode = runtime, mode
        self.token = secrets.token_urlsafe(48)
        atomic_write(self.config.admin_token_file, self.token.encode())
        atomic_write(directory / "config.json", canonical(value) + b"\n")
        self.client = NativeClient(self.config)
        self.report = {"scope": "native_service_synthetic_delivery", "backend": self.config.backend,
            "workspace_mode": mode, "runtime": runtime, "worker_protocol_version": WORKER_PROTOCOL_VERSION,
            "controller_worker_source_sha256": native.dispatch(directory, "identity", {})["worker_source_sha256"], "production_approved": False,
            "real_model_provider_tested": False, "real_agent_cli_tested": False,
            "http_mcp_transport_tested": False, "checks": {}, "passed": False}

    def call(self, method, params, token=None):
        return self.client.invoke(token or self.token, method, params)

    def wait(self, task, execution):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = self.call("task.status", {"task_id": task})
            record = next(r for r in status["execution_records"] if r["id"] == execution)
            if record["state"] not in ("starting", "running"):
                if record["state"] != "completed" or record.get("exit_code") != 0:
                    raise RuntimeError("Synthetic command failed: " + record["state"])
                return decode(self.call("task.logs", {"task_id": task, "execution_id": execution, "cursor": 0})["data"])
            time.sleep(.1)
        raise RuntimeError("Synthetic command did not complete")

    def execute(self, task, argv, token=None):
        record = self.call("task.exec", {"task_id": task, "argv": argv, "timeout_seconds": 60}, token)
        return self.wait(task, record["execution_id"])

    def run(self):
        self.source.mkdir()
        gitops.git(self.source, "init", "--template=", "-b", "main")
        (self.source / "answer.py").write_text("answer = 1\n")
        (self.source / "private.txt").write_text("synthetic file excluded from snapshot\n")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "synthetic audit input")
        base = gitops.resolve(self.source, "HEAD")
        gitops.git(self.source, "checkout", "--detach")
        ttl = min(30, self.config.limits["max_ttl_minutes"])
        task = self.call("task.create", {"repo": "synthetic", "base": base, "runtime": self.runtime,
            "network": "none", "workspace_mode": self.mode, "files": {"include": ["answer.py", "result.bin"], "exclude": []},
            "purpose": "synthetic full service delivery", "ttl_minutes": ttl, "idempotency_key": "synthetic-create"})
        checks = self.report["checks"]
        checks["task_create_ready"] = task["environment_state"] == "ready"
        self.report["image_digest"] = task["image_digest"]
        py = sys.executable
        if self.client.isolated:
            probe = json.loads(self.execute(task["id"], ["agenticsandbox", "probe", "--expected-uid",
                                  str(self.config.runtimes[self.runtime].get("task_uid", 10001))], task["task_token"]))
            checks["restricted_task_probe"] = probe.get("passed") is True
        self.execute(task["id"], [py, "-c", "from pathlib import Path; import subprocess; "
            "Path('answer.py').write_text('answer = 42\\n'); Path('result.bin').write_bytes(bytes(range(256))); "
            "subprocess.run(['git','add','--all'],check=True); subprocess.run(['git','commit','-m','synthetic result'],check=True)"], task["task_token"])
        checkpoint = self.call("task.checkpoint", {"task_id": task["id"]}, task["task_token"])
        self.call("task.destroy", {"task_id": task["id"]})
        restored = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint["id"],
            "idempotency_key": "synthetic-restore"})
        checks["checkpoint_destroy_restore"] = restored["generation"] == 1 and restored["environment_state"] == "ready"
        try:
            self.call("task.status", {"task_id": task["id"]}, task["task_token"])
            checks["old_token_revoked"] = False
        except SandboxError as exc:
            checks["old_token_revoked"] = exc.code == "unauthorized"
        result = self.call("task.submit", {"task_id": task["id"], "idempotency_key": "synthetic-submit"}, restored["task_token"])
        candidate = self.call("task.prepare_integration", {"result_id": result["id"], "target_branch": "main"})
        readonly = """from pathlib import Path
from answer import answer
assert answer == 42
assert Path('result.bin').read_bytes() == bytes(range(256))
for path in (Path('answer.py'),Path('new.py'),Path('.git/audit-write')):
    try:
        with path.open('ab') as stream: stream.write(b'forbidden')
    except PermissionError: continue
    raise RuntimeError('verification source is writable')
Path('../build/verified.txt').write_text('verified')
"""
        verify = readonly if self.client.isolated else "from answer import answer; assert answer == 42"
        validation = self.call("task.validate", {"candidate_id": candidate["id"], "runtime": self.runtime,
            "network": "none", "ttl_minutes": ttl, "commands": [[py, "-c", verify]]})
        self.wait(validation["task_id"], validation["execution_ids"][0])
        checks["fresh_verification"] = validation["task_id"] != task["id"]
        if self.client.isolated:
            checks["verification_source_readonly"] = True
        accepted = self.call("task.integrate", {"candidate_id": candidate["id"], "idempotency_key": "synthetic-integrate"})
        checks["result_integrated"] = accepted["integrated"] and gitops.git(self.source, "show", "main:answer.py") == b"answer = 42\n"
        checks["binary_preserved"] = gitops.git(self.source, "show", "main:result.bin") == bytes(range(256))
        checks["excluded_file_preserved"] = gitops.git(self.source, "show", "main:private.txt") == b"synthetic file excluded from snapshot\n"
        if self.mode == "repository":
            checks["result_commit_preserved"] = candidate["incoming_sha"] == result["result_sha"]
        self.report.update(result_sha=result["result_sha"], candidate_sha=candidate["candidate_sha"],
                           passed=all(checks.values()))

    def cleanup(self):
        complete = True
        for task in self.client.store.list("task"):
            try:
                status = self.call("task.status", {"task_id": task["id"]})
                for record in status.get("execution_records", []):
                    if record["state"] in ("starting", "running"):
                        self.call("task.cancel", {"task_id": task["id"], "execution_id": record["id"]})
                destroyed = self.call("task.destroy", {"task_id": task["id"], "abandon": True})
                if destroyed["environment_state"] != "destroyed":
                    complete = False
            except (SandboxError, RuntimeError, OSError, ValueError, KeyError):
                complete = False
        return complete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=native.BINARY)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path, help="Existing remote config with an approved runtime")
    source.add_argument("--local", action="store_true", help="Unsafe local protocol fixture with synthetic inputs only")
    parser.add_argument("--runtime", default="agentic")
    parser.add_argument("--workspace-mode", choices=("snapshot", "repository"), default="snapshot")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, help="New private directory to retain diagnostic state, including tokens")
    args = parser.parse_args()
    native.BINARY = args.binary.resolve()
    config = FixtureConfig({"backend": "local", "allow_unsafe_local": True,
        "runtimes": {args.runtime: {"networks": ["none"]}}}) if args.local else FixtureConfig.load(args.config)
    if not args.local and config.backend != "coder": parser.error("--config must use the Coder backend")
    output = args.output.resolve()
    with tempfile.TemporaryDirectory(prefix="agenticsandbox-service-audit-") as temporary:
        directory = args.work_dir.resolve() if args.work_dir else Path(temporary)
        if args.work_dir:
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            if directory.stat().st_mode & 0o077: raise RuntimeError("Audit work directory must be private")
        elif config.backend == "coder":
            # Keep recovery state if a remote failure prevents cleanup. The
            # directory contains tokens and must never be published as an artifact.
            directory = Path(tempfile.mkdtemp(prefix="agenticsandbox-service-recovery-"))
        audit = DeliveryAudit(config, args.runtime, args.workspace_mode, directory)
        try:
            audit.run()
        except (SandboxError, RuntimeError, OSError, ValueError, KeyError) as exc:
            audit.report["error"] = exc.code if isinstance(exc, SandboxError) else type(exc).__name__
        finally:
            audit.report["cleanup_complete"] = audit.cleanup()
        audit.report["passed"] &= audit.report["cleanup_complete"]
        audit.report["recovery_directory"] = str(directory) if args.work_dir or config.backend == "coder" else None
        atomic_write(output, canonical(audit.report) + b"\n")
        print(json.dumps({"passed": audit.report["passed"], "cleanup_complete": audit.report["cleanup_complete"],
            "report": str(output), "production_approved": False}))
        return 0 if audit.report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
