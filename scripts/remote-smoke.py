"""Exercise the native MCP/controller against a real SSH Docker host."""
import argparse
import base64
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import time
import uuid


class MCP:
    def __init__(self, binary, url, token, cwd):
        self.process = subprocess.Popen([str(binary), "mcp", "--url", url, "--token-file", str(token)],
            cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.number = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "remote-audit", "version": "1"}})

    def request(self, method, params):
        self.number += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.number, "method": method, "params": params}).encode() + b"\n")
        self.process.stdin.flush()
        with selectors.DefaultSelector() as sel:
            sel.register(self.process.stdout, selectors.EVENT_READ)
            if not sel.select(120):
                raise RuntimeError("MCP response timeout: " + method)
        response = json.loads(self.process.stdout.readline())
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return response["result"]

    def call(self, name, args):
        result = self.request("tools/call", {"name": name, "arguments": args})
        value = json.loads(result["content"][0]["text"])
        if result.get("isError"):
            raise RuntimeError(name + ": " + str(value))
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(5)


def completed(mcp, task, argv, accepted_codes=(0,)):
    e = mcp.call("task.exec", {"task_id": task, "argv": argv, "timeout_seconds": 15})
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status = mcp.call("task.status", {"task_id": task})
        record = next(r for r in status["execution_records"] if r["id"] == e["execution_id"])
        if record["state"] not in ("starting", "running"):
            logs = mcp.call("task.logs", {"task_id": task, "execution_id": e["execution_id"], "cursor": 0})
            if record["state"] != "completed" or record.get("exit_code") not in accepted_codes:
                raise RuntimeError("Sandbox command failed: " + str(record) + ": " + base64.b64decode(logs["data"]).decode(errors="replace"))
            return base64.b64decode(logs["data"])
        time.sleep(.1)
    raise RuntimeError("Sandbox execution did not complete")


def run(args):
    binary = args.binary.resolve()
    server = None
    clients, tasks = [], []
    checks = {}
    report = {"production_approved": False, "backend": "remote", "checks": checks}
    with tempfile.TemporaryDirectory(prefix="agenticsandbox-ssh-mcp-audit-", dir="/private/tmp" if Path("/private/tmp").exists() else None) as temp:
        root = Path(temp)
        if args.config:
            cfg = json.loads(args.config.read_text())
            token = Path(cfg["admin_token_file"])
            subprocess.run([str(binary), "init", "--config", str(args.config)], check=True, capture_output=True)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = "http://127.0.0.1:" + str(port)
            serverlog = (root / "controller.log").open("wb")
            server = subprocess.Popen([str(binary), "serve", "--config", str(args.config), "--port", str(port)], stdout=serverlog, stderr=serverlog)
            deadline = time.monotonic() + 15
            while True:
                if server.poll() is not None:
                    raise RuntimeError("Controller refused startup: " + (root / "controller.log").read_text()[-2000:])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.3):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Controller startup timed out")
                    time.sleep(.1)
        else:
            url, token = args.url, args.token_file.resolve()
        try:
            # Both bridges remain alive, proving they share one controller.
            clients.append(MCP(binary, url, token, root))
            clients.append(MCP(binary, url, token, Path("/")))
            a, b = clients
            available = a.request("tools/list", {})["tools"]
            checks["mcp_tools_and_global_working_directories"] = {t["name"] for t in available} >= {"task.create", "task.exec", "task.destroy", "repo.register", "sandbox.info"}
            checks["remote_controller"] = a.call("sandbox.info", {})["backend"] == "remote"
            for c in clients:
                task = c.call("task.create", {"runtime": "agentic", "network": "none", "role": "scratch", "purpose": "MCP SSH/Docker installation acceptance", "files": {"include": ["**"], "exclude": []}, "ttl_minutes": 10})
                tasks.append(task["id"])
                checks["isolated_" + str(len(tasks))] = task.get("isolated") is True and task.get("isolation_basis") == "docker_controls"
            a.call("task.write", {"task_id": tasks[0], "path": "hello.js", "data": base64.b64encode(b"require('fs').writeFileSync('output.txt', 'hello sandbox\\n'); console.log(JSON.stringify({uid:process.getuid(),cwd:process.cwd(),home:process.env.HOME}));\n").decode()})
            result = json.loads(completed(a, tasks[0], ["node", "hello.js"]))
            checks["restricted_task_uid_and_home"] = result == {"uid": 10001, "cwd": "/workspace/repo", "home": "/workspace/home"}
            checks["write_execute_read"] = base64.b64decode(a.call("task.read", {"task_id": tasks[0], "path": "output.txt"})["data"]) == b"hello sandbox\n"
            checks["separate_task_files"] = completed(b, tasks[1], ["/bin/sh", "-c", "test ! -e hello.js && test ! -e output.txt"]) == b""
            checks["git_commit"] = len(completed(a, tasks[0], ["/bin/sh", "-c", "git add hello.js output.txt && git commit -m 'MCP sandbox acceptance' >/dev/null && git rev-parse HEAD"]).strip()) == 40
            probe = json.loads(completed(a, tasks[0], ["agenticsandbox", "probe"], accepted_codes=(0, 1)))
            # The pinned image's probe expects a private Coder bootstrap file.
            # SSH Docker has no Coder bootstrap/credentials; require its absence
            # and retain every other UID/capability/seccomp/storage check.
            completed(a, tasks[0], ["/bin/sh", "-c", "test ! -e /run/coder/init.sh"])
            report["worker_probe"] = probe
            report["not_applicable_probe_checks"] = ["bootstrap_private"]
            checks["task_uid_capabilities_seccomp_and_control_storage"] = all(v for k, v in probe["checks"].items() if k != "bootstrap_private")
            # The second bridge can operate the first task without owning state.
            checks["shared_controller_sessions"] = b.call("task.status", {"task_id": tasks[0]})["id"] == tasks[0]
            if args.config:
                source = root / "source"
                source.mkdir()
                def git(*argv):
                    return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=MCP acceptance", "-c", "user.email=mcp-acceptance@example.invalid", "-C", str(source), *argv], stderr=subprocess.DEVNULL)
                git("init", "--template=", "-b", "main")
                (source / "math.js").write_text("console.log(2 + 3);\n")
                (source / ".env").write_text("FIXTURE_PRIVATE=excluded\n")
                git("add", "--all")
                git("commit", "-m", "fixture input")
                name = "mcp-audit-" + uuid.uuid4().hex[:12]
                a.call("repo.register", {"name": name, "path": str(source)})
                task = a.call("task.create", {"repo": name, "base": "HEAD", "runtime": "agentic", "network": "none", "files": {"include": ["math.js"], "exclude": ["**/.env*"]}, "ttl_minutes": 10})
                tasks.append(task["id"])
                checks["registered_repository_input_and_exclusion"] = completed(a, task["id"], ["/bin/sh", "-c", "test ! -e .env && node math.js"]) == b"5\n"
        finally:
            cleanup = True
            for task in tasks:
                try:
                    clients[0].call("task.destroy", {"task_id": task, "abandon": True})
                except Exception:
                    cleanup = False
            checks["own_tasks_destroyed"] = cleanup
            for c in clients:
                c.close()
            if server:
                server.terminate()
                server.wait(10)
                serverlog.close()
        report["passed"] = all(checks.values())
        report["check_count"] = len(checks)
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        if not report["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--config", type=Path)
    group.add_argument("--url")
    p.add_argument("--token-file", type=Path)
    p.add_argument("--output", type=Path)
    run(p.parse_args())
