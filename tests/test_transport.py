"""Native executable transport tests; fixtures never call real providers."""
import base64
import concurrent.futures
import http.server
import http.client
import json
import os
from pathlib import Path
import re
import socket
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from support import native
BINARY = native.BINARY


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_status_line(connection):
    response = b""
    while b"\r\n" not in response and len(response) < 16384:
        more = connection.recv(2048)
        if not more:
            break
        response += more
    return response


def tls_fixture(root):
    cert, key, ca = root / "cert.pem", root / "key.pem", root / "ca.pem"
    ca_key, csr, extensions = root / "ca.key", root / "server.csr", root / "extensions.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    commands = [
        ["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca),"-days","1","-subj","/CN=Fixture CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl","req","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(csr),"-subj","/CN=localhost"],
        ["openssl","x509","-req","-in",str(csr),"-CA",str(ca),"-CAkey",str(ca_key),"-CAcreateserial","-out",str(cert),"-days","1","-extfile",str(extensions)]
    ]
    for command in commands:
        subprocess.run(command,check=True,capture_output=True)
    return cert, key, ca


class TransportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agenticsandbox-rust-http-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config.json"
        self.admin = self.root / "state/admin.token"
        self.cert, self.key, self.ca = tls_fixture(self.root)
        self.requests = []
        self.response = b'{"ok":true}'
        self.content_type = "application/json"
        self.listen_port = port()
        self.value = {"backend": "local", "allow_unsafe_local": True, "state_dir": "state", "admin_token_file": "state/admin.token",
                      "runtimes": {"test": {"networks": ["none"]}}, "networks": {"none": {}}, "repos": {},
                      "public_url": "https://localhost:" + str(self.listen_port), "agents": {}, "reconcile_interval_seconds": 60}
        self.write_config()
        subprocess.run([str(BINARY), "init", "--config", str(self.config)], check=True, capture_output=True)
        self.token = self.admin.read_text().strip()

    def write_config(self):
        self.config.write_text(json.dumps(self.value))

    def start(self, tls=False, environment=None):
        args = [str(BINARY), "serve", "--config", str(self.config), "--port", str(self.listen_port)]
        if tls:
            args += ["--tls-cert", str(self.cert), "--tls-key", str(self.key)]
        env = {k:v for k,v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        env.update(NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1")
        env.update(environment or {})
        self.server = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("Native HTTP server failed: " + self.server.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1", self.listen_port), timeout=.1):
                    return
            except OSError:
                time.sleep(.02)
        self.fail("Native HTTP server did not listen")

    def stop(self):
        self.server.terminate()
        self.server.wait(timeout=5)
        self.server.stderr.close()

    def request(self, path, payload, token=None, headers=None, tls=False, trust=True):
        headers = {"Content-Type": "application/json", **(headers or {})}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        url = ("https://localhost:" if tls else "http://127.0.0.1:") + str(self.listen_port) + path
        ctx = ssl.create_default_context(cafile=str(self.ca) if trust else None)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    def rpc(self, method, params, token=None, tls=False):
        status, data, _ = self.request("/rpc", {"method": method, "params": params}, token or self.token, tls=tls)
        self.assertEqual(status, 200, data)
        return json.loads(data)["result"]


    def test_http_authentication_and_task_scope(self):
        self.start()
        status, _, _ = self.request("/rpc", {"method": "task.create"})
        self.assertEqual(status, 401)
        a = self.rpc("task.create", {"runtime": "test", "role": "scratch"})
        b = self.rpc("task.create", {"runtime": "test", "role": "scratch"})
        status, data, headers = self.request("/rpc", {"method": "task.status", "params": {"task_id": b["id"]}}, a["task_token"])
        self.assertEqual(status, 403)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("synthetic-provider-key", data.decode())

    def test_controller_lock_prevents_second_direct_controller(self):
        self.start()
        result = subprocess.run([str(BINARY), "call", "task.reconcile", "--config", str(self.config), "--token-file", str(self.admin)], input=b"{}", capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stderr)["error"], "controller_running")

    def health(self, tls=False):
        context = ssl.create_default_context(cafile=str(self.ca))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        start = time.monotonic()
        with opener.open(("https://localhost:" if tls else "http://127.0.0.1:") + str(self.listen_port) + "/health", timeout=1) as response:
            self.assertEqual(response.status, 200)
        self.assertLess(time.monotonic() - start, 1)

    def test_slow_tls_handshakes_and_headers_leave_health_available(self):
        self.value["limits"] = {"http_header_timeout_ms": 500}
        self.write_config()
        self.start(tls=True)
        connections = []
        try:
            for _ in range(20):
                connections.append(socket.create_connection(("127.0.0.1", self.listen_port), timeout=1))
            context = ssl.create_default_context(cafile=str(self.ca))
            for _ in range(20):
                raw = socket.create_connection(("127.0.0.1", self.listen_port), timeout=1)
                connection = context.wrap_socket(raw, server_hostname="localhost")
                connection.sendall(b"POST /rpc HTTP/1.1\r\n")
                connections.append(connection)
            self.health(tls=True)
            time.sleep(.8)
            for connection in connections:
                try:
                    response = http_status_line(connection)
                    self.assertTrue(response == b"" or b"408" in response, response)
                except (ssl.SSLError, ConnectionResetError):
                    pass
            self.health(tls=True)
        finally:
            for connection in connections:
                connection.close()

    def test_stalled_authenticated_bodies_have_absolute_deadline(self):
        self.value["limits"] = {"http_body_timeout_seconds": 1}
        self.write_config()
        self.start()
        connections = []
        try:
            for _ in range(20):
                connection = socket.create_connection(("127.0.0.1", self.listen_port), timeout=2)
                connection.sendall(("POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + self.token + "\r\nContent-Length: 10000\r\n\r\n{").encode())
                connections.append(connection)
            self.health()
            for _ in range(3):
                time.sleep(.25)
                connections[0].sendall(b" ")
            time.sleep(.45)
            self.assertIn(b"408", http_status_line(connections[0]))
            self.health()
        finally:
            for connection in connections:
                connection.close()

    def test_ingress_budget_rejects_large_partial_body_and_recovers(self):
        self.value["limits"] = {"max_http_buffer_bytes": 8192}
        self.write_config()
        self.start()
        with socket.create_connection(("127.0.0.1", self.listen_port), timeout=2) as connection:
            connection.sendall(("POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + self.token + "\r\nContent-Length: 20000\r\n\r\n").encode() + b"x" * 12000)
            self.assertIn(b"503", http_status_line(connection))
        self.health()
        self.rpc("task.create", {"runtime": "test", "role": "scratch"})

    def test_concurrent_create_idempotency_and_quota(self):
        self.value["limits"] = {"max_tasks": 2}
        self.write_config()
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.rpc, "task.create", {"runtime": "test", "role": "scratch", "idempotency_key": "shared"}) for _ in range(8)]
            tasks = [future.result() for future in futures]
            self.assertEqual(len({task["id"] for task in tasks}), 1)
            replies = list(pool.map(lambda i: self.request("/rpc", {"method": "task.create", "params": {"runtime": "test", "role": "scratch", "idempotency_key": "other-" + str(i)}}, self.token)[0], range(8)))
        self.assertEqual(replies.count(200), 1, replies)
        self.assertEqual(replies.count(429), 7, replies)

    def test_unrelated_status_and_cancel_during_blocked_git_export(self):
        source = self.root / "source"
        source.mkdir()
        system_git = shutil.which("git")
        subprocess.run([system_git, "init", "--template=", "-b", "main", str(source)], check=True, capture_output=True)
        (source / "file").write_bytes(b"fixture\n")
        subprocess.run([system_git, "-C", str(source), "add", "."], check=True, capture_output=True)
        subprocess.run([system_git, "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture"], check=True, capture_output=True)
        self.value["repos"] = {"fixture": str(source)}
        self.write_config()
        wrappers = self.root / "bin"
        wrappers.mkdir()
        entered, release = self.root / "entered", self.root / "release"
        wrapper = wrappers / "git"
        wrapper.write_text("#!" + sys.executable + "\nimport os,sys,time\nfrom pathlib import Path\n"
            + "if '--batch' in sys.argv and " + repr(str(source)) + " in sys.argv:\n"
            + " Path(" + repr(str(entered)) + ").touch()\n deadline=time.monotonic()+6\n"
            + " while not Path(" + repr(str(release)) + ").exists() and time.monotonic()<deadline: time.sleep(.02)\n"
            + "os.execv(" + repr(system_git) + ", ['git', *sys.argv[1:]])\n")
        wrapper.chmod(0o755)
        self.start(environment={"PATH": str(wrappers) + os.pathsep + os.environ["PATH"]})
        task = self.rpc("task.create", {"runtime": "test", "role": "scratch"})
        execution = self.rpc("task.exec", {"task_id": task["id"], "argv": ["/bin/sleep", "10"]})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.rpc, "task.create", {"runtime": "test", "repo": "fixture", "base": "main", "files": {"include": ["**"]}})
            try:
                deadline = time.monotonic() + 4
                while not entered.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(entered.exists(), "Git latency fixture did not enter batch export")
                start = time.monotonic()
                self.rpc("task.status", {"task_id": task["id"]})
                self.rpc("task.cancel", {"task_id": task["id"], "execution_id": execution["execution_id"]})
                self.assertLess(time.monotonic() - start, 1)
                self.assertFalse(future.done(), "Slow export must still be pending")
            finally:
                release.touch()
            self.assertIn("id", future.result())


    def test_mcp_stdio_lists_schemas_and_returns_scoped_results(self):
        requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"}, {"method": "notifications/initialized"},
                    {"id": 2, "method": "tools/list"}, {"id": 3, "method": "tools/call", "params": {"name": "task.create", "arguments": {"runtime": "test", "role": "scratch"}}}]
        result = subprocess.run([str(BINARY), "mcp", "--config", str(self.config), "--token-file", str(self.admin)],
                                input=("\n".join(json.dumps(r) for r in requests) + "\n").encode(), capture_output=True, check=True)
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["result"]["serverInfo"]["version"], "0.2.0")
        tools = responses[1]["result"]["tools"]
        self.assertEqual(len(tools), 20)
        self.assertTrue({"sandbox.info", "repo.register"} <= {t["name"] for t in tools})
        self.assertNotIn("agent.start", {t["name"] for t in tools})
        self.assertTrue(all(t["inputSchema"]["additionalProperties"] is False for t in tools))
        self.assertFalse(responses[2]["result"]["isError"])

    def test_declared_mcp_tools_match_service_dispatch(self):
        # The tool list is hand-written next to the dispatch arms. Without this
        # check, a tool could be advertised with no handler, or a handler could
        # be unreachable because it was never declared.
        root = Path(__file__).resolve().parents[1]
        declared = {tool["name"] for tool in json.loads((root / "src/tools.json").read_text())}
        self.assertEqual(len(declared), 20)
        service = (root / "src/service/mod.rs").read_text()
        start = service.index("    pub fn invoke(")
        body = service[start:service.index("\n    }\n", start)]
        handled = set(re.findall(r'"((?:task|agent|repo|sandbox)\.[a-z_]+)"', body))
        self.assertEqual(declared, handled)

    def test_https_private_ca_checks_certificate_and_hostname(self):
        self.start(tls=True)
        status, _, _ = self.request("/rpc", {"method": "task.reconcile", "params": {}}, self.token, tls=True)
        self.assertEqual(status, 200)
        with self.assertRaises(urllib.error.URLError):
            self.request("/rpc", {}, self.token, tls=True, trust=False)
        env = {k:v for k,v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        result = subprocess.run([str(BINARY), "call", "task.reconcile", "--url", "https://localhost:" + str(self.listen_port),
                                 "--ca-file", str(self.ca), "--token-file", str(self.admin)], input=b"{}", capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        # The private CA must not disable the native client's hostname check.
        result = subprocess.run([str(BINARY), "call", "task.reconcile", "--url", "https://127.0.0.1:" + str(self.listen_port),
                                 "--ca-file", str(self.ca), "--token-file", str(self.admin)], input=b"{}", capture_output=True, env=env)
        self.assertNotEqual(result.returncode, 0)

    def test_mcp_https_uses_private_ca_and_enforces_task_scope(self):
        self.start(tls=True)
        def rpc(method, params):
            status, data, _ = self.request("/rpc", {"method": method, "params": params}, self.token, tls=True)
            self.assertEqual(status, 200, data)
            return json.loads(data)["result"]
        a = rpc("task.create", {"runtime": "test", "role": "scratch"})
        b = rpc("task.create", {"runtime": "test", "role": "scratch"})
        credential = self.root / "task.token"
        credential.write_text(a["task_token"])
        credential.chmod(0o600)
        requests = [{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {
            "name": "task.status", "arguments": {"task_id": task["id"]}}}
            for i, task in enumerate((a, b), 1)]
        env = {k:v for k,v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        result = subprocess.run([str(BINARY), "mcp", "--url", "https://localhost:" + str(self.listen_port),
            "--ca-file", str(self.ca), "--token-file", str(credential)],
            input=("\n".join(json.dumps(r) for r in requests) + "\n").encode(), capture_output=True, check=True, env=env)
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(responses), 2)
        self.assertFalse(responses[0]["result"]["isError"])
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertIn("forbidden", responses[1]["result"]["content"][0]["text"])

    def test_invalid_tls_does_not_bind_socket(self):
        self.cert.write_text("invalid certificate")
        result = subprocess.run([str(BINARY), "serve", "--config", str(self.config), "--port", str(self.listen_port),
                                 "--tls-cert", str(self.cert), "--tls-key", str(self.key)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", self.listen_port))

    def test_duplicate_length_and_compression_are_rejected(self):
        self.start()
        with socket.create_connection(("127.0.0.1", self.listen_port)) as conn:
            conn.sendall(("POST /rpc HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\nAuthorization: Bearer " + self.token + "\r\nContent-Type: application/json\r\n\r\n{}").encode())
            response = b""
            while b"\r\n" not in response:
                part = conn.recv(4096)
                self.assertTrue(part)
                response += part
            self.assertIn(b"400", response.split(b"\r\n")[0])
        status, _, _ = self.request("/rpc", {}, self.token, {"Content-Encoding": "gzip"})
        self.assertEqual(status, 400)










