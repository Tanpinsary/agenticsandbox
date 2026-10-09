"""Subprocess clients and state inspection for testing the Rust product.

Configuration validation, permissions, capabilities and task operations run in
the native executable. These fixtures never implement a controller or worker.
"""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from .json_helpers import SandboxError, atomic_write, canonical

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("AGENTICSANDBOX_TEST_BINARY", ROOT / "target/debug/agenticsandbox")).resolve()
WORKER_PROTOCOL_VERSION = 1
# Deliberate fixture budgets, passed to the real Rust validator.
LIMITS = {"max_file_bytes": 8388608, "max_total_bytes": 67108864, "max_files": 10000,
          "max_ttl_minutes": 360, "max_output_bytes": 4194304, "max_execution_seconds": 3600,
          "max_scan_entries": 100000, "max_tasks": 32, "max_concurrent_executions": 8,
          "max_bundle_bytes": 67108864}


class FixtureConfig:
    """Mutable test inputs, with no product configuration validation."""
    def __init__(self, value, base=Path(".")):
        self.value = value
        self.backend = value.get("backend", "coder")
        self.state_dir = (base / value.get("state_dir", ".state")).resolve()
        self.admin_token_file = (base / value.get("admin_token_file", ".state/admin.token")).resolve()
        self.repos = {name: (base / path).resolve() for name, path in value.get("repos", {}).items()}
        self.runtimes, self.agents = value.get("runtimes", {}), value.get("agents", {})
        self.networks = value.get("networks", {"none": {}})
        self.limits = {**LIMITS, **value.get("limits", {})}

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        return cls(json.loads(path.read_text()), path.parent)


class StateInspector:
    """Inspect or deliberately corrupt existing native state for recovery tests."""
    def __init__(self, root):
        self.path = root / "control.sqlite3"

    def get(self, kind, identifier):
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        return json.loads(row[0])

    def list(self, kind):
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT data FROM records WHERE kind=? ORDER BY id", (kind,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def put(self, kind, record):
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO records VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                       (kind, record["id"], canonical(record).decode()))


def dispatch(root, operation, request):
    result = subprocess.run([str(BINARY), "worker"],
        input=canonical({"root": str(root), "operation": operation, "request": request}),
        capture_output=True, timeout=120)
    response = json.loads(result.stdout)
    if result.returncode or "error" in response:
        raise SandboxError(response["error"], response.get("code", "worker_error"), 409)
    return response["result"]


class NativeClient:
    def __init__(self, config):
        self.config = config
        config.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.store = StateInspector(config.state_dir)

    @property
    def isolated(self):
        return self.config.backend == "coder"

    def root(self, task):
        return self.config.state_dir / "environments" / task["id"] / str(task.get("generation", 0))

    def exists(self, task):
        return self.root(task).is_dir()

    def artifact(self, kind, identifier):
        return self.config.state_dir / "artifacts" / kind / (identifier + ".json")

    def persist_execution(self, task, record):
        self.store.put("execution", {**record, "task_id": task["id"], "generation": task.get("generation", 0)})

    def invoke(self, token, method, params):
        config, credential = self.config.state_dir / "fixture-config.json", self.config.state_dir / "fixture-client.token"
        value = {**self.config.value, "state_dir": str(self.config.state_dir),
                 "admin_token_file": str(self.config.admin_token_file), "limits": self.config.limits,
                 "repos": {k: str(v) for k, v in self.config.repos.items()}, "runtimes": self.config.runtimes,
                 "agents": self.config.agents, "networks": self.config.networks}
        atomic_write(config, canonical(value))
        atomic_write(credential, token.encode())
        result = subprocess.run([str(BINARY), "call", "--config", str(config), "--token-file", str(credential), method],
                                input=canonical(params), capture_output=True, timeout=120)
        if result.returncode:
            error = json.loads(result.stderr)
            raise SandboxError(error["message"], error["error"], error.get("status", 400))
        return json.loads(result.stdout)
