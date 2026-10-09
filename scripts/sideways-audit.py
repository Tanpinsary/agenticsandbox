"""Bounded lateral diagnostics against the native binary and candidate image.

This is an assessment, not an isolation approval. Some diagnostics deliberately
record a failed guarantee. All repositories, servers, containers and volumes are
synthetic and private to this invocation; no real provider or Coder is called.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protocol(binary):
    with tempfile.TemporaryDirectory(prefix="sideways-protocol-") as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        def git(*argv):
            return subprocess.check_output(["git", "-C", str(source), *argv], stderr=subprocess.DEVNULL)
        git("init", "--template=", "-b", "main")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        (source / "public.txt").write_text("original\n")
        (source / "secret.txt").write_text("synthetic-private-canary\n")
        git("add", ".")
        git("commit", "-m", "fixture")
        base = git("rev-parse", "HEAD").decode().strip()
        config = root / "config.json"
        state = root / "state"
        admin = root / "admin"
        value = {"backend": "local", "allow_unsafe_local": True,
                 "state_dir": str(state), "admin_token_file": str(admin),
                 "repos": {"fixture": str(source)},
                 "runtimes": {"fixture": {"networks": ["none"]}},
                 "networks": {"none": {}}, "reconcile_interval_seconds": 30}
        config.write_text(json.dumps(value))
        subprocess.run([binary, "init", "--config", str(config)], check=True, capture_output=True)
        def call(method, params, token=None):
            credential = admin
            if token:
                credential = root / "client"
                credential.write_text(token)
                credential.chmod(0o600)
            result = subprocess.run([binary, "call", method, "--config", str(config),
                                     "--token-file", str(credential)],
                                    input=json.dumps(params).encode(), capture_output=True, timeout=40)
            return result.returncode, json.loads(result.stderr if result.returncode else result.stdout)
        def ok(method, params, token=None):
            code, response = call(method, params, token)
            if code:
                raise RuntimeError(response)
            return response
        def create(mode="snapshot", **extra):
            return ok("task.create", {"repo": "fixture", "base": base, "runtime": "fixture",
                     "workspace_mode": mode, "files": {"include": ["public.txt"], "exclude": []}, **extra})
        checks = {}
        a = create()
        snapshot = state / "environments" / a["id"] / "0/repo"
        history = subprocess.check_output(["git", "-C", str(snapshot), "log", "--all", "-p"])
        checks["snapshot_erases_private_history"] = {"passed": not (snapshot / "secret.txt").exists()
            and b"synthetic-private-canary" not in history}
        b = create("repository")
        full = state / "environments" / b["id"] / "0/repo"
        code, response = call("task.read", {"task_id": b["id"], "path": "secret.txt"}, b["task_token"])
        # Repository mode's file policy is explicitly not a confidentiality boundary.
        checks["repository_policy_is_delivery_scope"] = {"passed": code != 0
            and response.get("error") == "forbidden" and (full / "secret.txt").is_file(),
            "file_api_denied": code != 0, "shell_can_read_excluded_file": (full / "secret.txt").is_file()}
        code, response = call("task.status", {"task_id": b["id"]}, a["task_token"])
        checks["cross_task_token_denied"] = {"passed": code != 0 and response.get("error") == "forbidden"}
        (source / "public.txt").write_text("uncommitted edit\n")
        c = create()
        committed = state / "environments" / c["id"] / "0/repo/public.txt"
        code, response = call("task.create", {"repo": "fixture", "base": base, "runtime": "fixture",
            "include_dirty": True, "files": {"include": ["public.txt"], "exclude": []}})
        checks["dirty_input_is_explicitly_unsupported"] = {"passed": code != 0,
            "default_uses_committed_version": committed.read_text() == "original\n"}
        params = {"task_id": a["id"], "argv": ["/usr/bin/true"], "idempotency_key": "same-command"}
        first = ok("task.exec", params, a["task_token"])
        second = ok("task.exec", params, a["task_token"])
        code, response = call("task.exec", {**params, "argv": ["/usr/bin/false"]}, a["task_token"])
        checks["restart_idempotency_and_parameter_conflict"] = {"passed": first["execution_id"] == second["execution_id"]
            and code != 0 and response.get("error") == "conflict", "error": response.get("error")}
        # Measure the actual implementation on a small synthetic repository.
        bulk = source / "bulk"
        bulk.mkdir()
        for i in range(512):
            (bulk / f"f{i:04d}.txt").write_text("sideways benchmark needle\n" * 8)
        git("add", "bulk")
        git("commit", "-m", "bulk fixture")
        bulk_base = git("rev-parse", "HEAD").decode().strip()
        start = time.monotonic()
        d = ok("task.create", {"repo": "fixture", "base": bulk_base, "runtime": "fixture",
            "files": {"include": ["bulk/**"], "exclude": []}})
        create_elapsed = time.monotonic() - start
        start = time.monotonic()
        search = ok("task.search", {"task_id": d["id"], "query": "benchmark"}, d["task_token"])
        checks["small_repository_performance"] = {"passed": True, "files": 512,
            "input_bytes": 512 * len("sideways benchmark needle\n" * 8),
            "create_seconds": create_elapsed, "search_seconds": time.monotonic() - start,
            "matches_returned": len(search["matches"]), "truncated": search["truncated"]}
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        server = subprocess.Popen([binary, "serve", "--config", str(config), "--port", str(port)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        sockets = []
        try:
            for _ in range(100):
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=.2):
                        break
                except OSError:
                    time.sleep(.02)
            creation = {}
            def request(method, params):
                req = urllib.request.Request(f"http://127.0.0.1:{port}/rpc",
                    data=json.dumps({"method": method, "params": params}).encode(),
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer " + admin.read_text().strip()})
                with opener.open(req, timeout=40) as response:
                    return json.load(response)
            def create_in_background():
                start = time.monotonic()
                try:
                    creation["response"] = request("task.create", {"repo": "fixture", "base": bulk_base,
                        "runtime": "fixture", "files": {"include": ["bulk/**"], "exclude": []}})
                except Exception as error:
                    creation["error"] = type(error).__name__
                creation["seconds"] = time.monotonic() - start
            creator = threading.Thread(target=create_in_background)
            creator.start()
            time.sleep(.3)
            start = time.monotonic()
            response = request("task.status", {"task_id": a["id"]})
            elapsed = time.monotonic() - start
            creator.join(timeout=40)
            checks["unrelated_task_status_during_creation"] = {"passed": elapsed < 1,
                "status_seconds": elapsed, "creation_seconds": creation.get("seconds"),
                "creation_succeeded": "result" in creation.get("response", {}),
                "status_succeeded": "result" in response}
            for _ in range(16):
                connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                connection.sendall(b"POST /rpc HTTP/1.1\r\n")
                sockets.append(connection)
            time.sleep(.3)
            start = time.monotonic()
            try:
                with opener.open(f"http://127.0.0.1:{port}/health", timeout=1):
                    available = True
            except OSError:
                available = False
            blocked = time.monotonic() - start
            for connection in sockets:
                connection.close()
            sockets.clear()
            with opener.open(f"http://127.0.0.1:{port}/health", timeout=3) as response:
                recovered = response.status == 200
            checks["bounded_slow_connections"] = {"passed": available,
                "connections": 16, "unauthenticated": True, "health_available_within_one_second": available,
                "probe_seconds": blocked, "recovered_after_release": recovered}
        finally:
            for connection in sockets:
                connection.close()
            server.terminate()
            server.wait(timeout=5)
        return checks


def docker(image):
    sys.path.insert(0, str(ROOT / "tests"))
    audit_module = module("sideways_docker_base", ROOT / "scripts/docker-runtime-audit.py")
    audit = audit_module.DockerAudit(image)
    checks = {}
    try:
        name = audit.create("sideways")
        audit.docker("network", "disconnect", "bridge", name)
        audit.install(name, "fixture")
        # Only one bounded child is created. It exits by itself in four seconds.
        program = """import os,time
pid=os.fork()
if pid==0:
    os.setsid()
    os.close(1); os.close(2)
    time.sleep(3)
    open('/workspace/tmp/escaped-after-timeout','w').write('bounded canary')
    time.sleep(1)
    os._exit(0)
time.sleep(10)
"""
        identifier = audit.start(name, ["python3", "-c", program], timeout=1)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            record = audit.worker(name, "execution", {"id": identifier})
            if record["state"] not in ("starting", "running"):
                break
            time.sleep(.1)
        time.sleep(2.5)
        escaped = audit.docker("exec", name, "python3", "-c",
            "from pathlib import Path;print(Path('/workspace/tmp/escaped-after-timeout').exists())").strip() == b"True"
        checks["timeout_covers_detached_descendants"] = {"passed": not escaped,
            "execution_state": record["state"], "descendant_wrote_after_timeout": escaped,
            "bounded_descendant_lifetime_seconds": 4}
        cancel_program = program.replace("escaped-after-timeout", "escaped-after-cancel")
        identifier = audit.start(name, ["python3", "-c", cancel_program], timeout=20)
        time.sleep(.5)
        audit.worker(name, "cancel", {"id": identifier})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            record = audit.worker(name, "execution", {"id": identifier})
            if record["state"] not in ("starting", "running"):
                break
            time.sleep(.1)
        time.sleep(3)
        escaped = audit.docker("exec", name, "python3", "-c",
            "from pathlib import Path;print(Path('/workspace/tmp/escaped-after-cancel').exists())").strip() == b"True"
        checks["cancel_covers_detached_descendants"] = {"passed": not escaped,
            "execution_state": record["state"], "descendant_wrote_after_cancel": escaped,
            "bounded_descendant_lifetime_seconds": 4}
        # Inspect live descendants at the terminal boundary as well as their
        # later file activity. Every diagnostic child also has its own deadline.
        for case, detach, finish in (
            ("double_fork_ignores_term", "os.setsid(); child=os.fork();\n    if child: os._exit(0)", "timeout"),
            ("new_process_group", "os.setpgid(0,0)", "timeout"),
            ("completed_main_daemon", "os.setsid()", "completed"),
        ):
            program = """import os,time,signal
from pathlib import Path
base=Path('/workspace/tmp/CASE')
pid=os.fork()
if pid==0:
    DETACH
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    os.close(1); os.close(2)
    base.with_suffix('.pid').write_text(str(os.getpid()))
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        base.with_suffix('.tick').write_text(str(time.monotonic()))
        time.sleep(.1)
    os._exit(0)
deadline=time.monotonic()+2
while not base.with_suffix('.pid').exists() and time.monotonic()<deadline: time.sleep(.01)
PARENT
""".replace("CASE", case).replace("DETACH", detach).replace("PARENT", "os._exit(0)" if finish == "completed" else "time.sleep(10)")
            identifier = audit.start(name, ["python3", "-c", program], timeout=1 if finish == "timeout" else 10)
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                record = audit.worker(name, "execution", {"id": identifier})
                if record["state"] not in ("starting", "running"):
                    break
                time.sleep(.05)
            inspection = """import json,time
from pathlib import Path
base=Path('/workspace/tmp/CASE')
pid=int(base.with_suffix('.pid').read_text())
before=base.with_suffix('.tick').read_text()
alive=Path('/proc/'+str(pid)).exists()
time.sleep(.5)
print(json.dumps({'descendant_alive_at_terminal':alive,'writes_after_terminal':before!=base.with_suffix('.tick').read_text()}))
""".replace("CASE", case)
            details = json.loads(audit.result(name, audit.start(name, ["python3", "-c", inspection])))
            checks[case] = {"passed": record["state"] == finish and not any(details.values()),
                            "execution_state": record["state"], **details}
        independent = audit.start(name, ["python3", "-c", "import time;time.sleep(8);print('independent-completed')"], timeout=12)
        victim = audit.start(name, ["python3", "-c", "import time;time.sleep(10)"], timeout=1)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            victim_record = audit.worker(name, "execution", {"id": victim})
            if victim_record["state"] not in ("starting", "running"):
                break
            time.sleep(.05)
        independent_record = audit.worker(name, "execution", {"id": independent})
        output = audit.result(name, independent)
        checks["cleanup_does_not_kill_other_execution"] = {"passed": victim_record["state"] == "timeout"
            and independent_record["state"] == "running" and b"independent-completed" in output}
        # Verify ordinary developer tooling's need for localhost sockets.
        output = audit.result(name, audit.start(name, ["python3", "-c", """import socket,json
try:
    s=socket.socket(); s.bind(('127.0.0.1',0)); s.close(); allowed=True
except OSError:
    allowed=False
print(json.dumps({'localhost_server_allowed':allowed}))
"""]))
        checks["network_none_blocks_local_development_servers"] = {"passed": True, **json.loads(output)}
        # Real Linux enforcement, rather than local backend file API assertions.
        verification = audit.create("readonly")
        audit.docker("network", "disconnect", "bridge", verification)
        audit.install(verification, "fixture", read_only=True)
        output = audit.result(verification, audit.start(verification, ["python3", "-c", """import json
try:
    open('fixture.py','w').write('changed'); denied=False
except PermissionError:
    denied=True
open('/workspace/build/output','w').write('build output')
print(json.dumps({'source_write_denied':denied,'build_write_allowed':True}))
"""]))
        result = json.loads(output)
        checks["verification_enforces_readonly_source"] = {"passed": all(result.values()), **result}
    finally:
        checks["isolated_resources_cleaned"] = {"passed": audit.cleanup()}
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--image", help="Optional full local sha256 image ID")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    binary = str(args.binary.resolve())
    before = sha(binary)
    report = {"scope": "bounded_lateral_diagnostics", "production_approved": False,
              "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "audit_script_sha256": sha(__file__),
              "real_model_provider_tested": False, "coder_connected": False,
              "binary_sha256": before, "image": args.image,
              "protocol": protocol(binary)}
    if args.image:
        report["docker"] = docker(args.image)
    report["binary_unchanged"] = sha(binary) == before
    identity = json.loads(subprocess.check_output([binary, "worker"],
        input=b'{"root":"/tmp","operation":"identity","request":{}}'))["result"]
    report["worker_source_sha256"] = identity["worker_source_sha256"]
    report["architecture"] = identity["architecture"]
    report["diagnostics_complete"] = True
    report["guarantees_passed"] = all(result["passed"] for group in ("protocol", "docker")
                                    for result in report.get(group, {}).values())
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(args.output), "sha256": sha(args.output),
        "observed_failed_guarantees": [f"{group}/{name}" for group in ("protocol", "docker")
            for name, result in report.get(group, {}).items() if not result["passed"]]}))


if __name__ == "__main__":
    main()
