"""End-to-end delivery regressions: every operation calls the Rust executable."""
import json
import os
import subprocess
import shutil
import shlex
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from support import git as gitops
from support.native import FixtureConfig, NativeClient, dispatch
from support.json_helpers import SandboxError, atomic_write, decode, digest, encode

class DeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agenticsandbox-test-", dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        gitops.git(self.source, "init", "--template=", "-b", "main")
        (self.source / "src").mkdir()
        (self.source / "src/main.py").write_text("answer = 1\n")
        (self.source / ".env").write_text("TOP_SECRET=should-not-be-visible\n")
        (self.source / "private.txt").write_text("private content")
        (self.source / ".gitignore").write_text("__pycache__/\n")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "initial")
        self.base = gitops.resolve(self.source, "HEAD")
        gitops.git(self.source, "checkout", "--detach")
        self.config = FixtureConfig({"backend": "local", "allow_unsafe_local": True, "state_dir": str(self.root / "state"),
            "admin_token_file": str(self.root / "admin.token"), "repos": {"project": str(self.source)},
            "runtimes": {"python": {"networks": ["none"]}}, "networks": {"none": {}},
            "limits": {"max_execution_seconds": 30}})
        self.token = "test-admin-" + "x" * 40
        atomic_write(self.config.admin_token_file, self.token.encode())
        self.client = NativeClient(self.config)
        self.executions = []

    def tearDown(self):
        for task_id, execution_id in self.executions:
            try:
                self.client.invoke(self.token, "task.cancel", {"task_id": task_id, "execution_id": execution_id})
            except SandboxError:
                pass
        self.temp.cleanup()

    def call(self, method, params, token=None):
        return self.client.invoke(token or self.token, method, params)

    def create(self, key=None):
        request = {"repo": "project", "base": self.base, "runtime": "python", "network": "none",
                   "files": {"include": ["src/**"], "exclude": ["**/.env*"]}, "purpose": "fix answer"}
        if key:
            request["idempotency_key"] = key
        return self.call("task.create", request)

    def run_command(self, task, code):
        execution = self.call("task.exec", {"task_id": task["id"], "argv": [sys.executable, "-c", code], "timeout_seconds": 5})
        self.executions.append((task["id"], execution["execution_id"]))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            record = next(r for r in self.call("task.status", {"task_id": task["id"]})["execution_records"] if r["id"] == execution["execution_id"])
            if record["state"] not in ("starting", "running"):
                self.assertEqual(record["state"], "completed", record)
                self.assertEqual(record["exit_code"], 0, record)
                return execution
            time.sleep(0.05)
        self.fail("Execution did not finish")

    def commit(self, task):
        repo = self.client.root(task) / "repo"
        gitops.git(repo, "add", "--all")
        gitops.git(repo, "commit", "-m", "task change")

    def test_repository_registration_persists_and_cannot_rebind(self):
        self.config.repos = {}
        registered = self.call("repo.register", {"name": "project", "path": str(self.source)})
        self.assertEqual(registered["head"], self.base)
        self.assertIn("project", self.call("sandbox.info", {})["repositories"])
        task = self.create()
        self.assertEqual(decode(self.call("task.read", {"task_id": task["id"], "path": "src/main.py"})["data"]), b"answer = 1\n")
        with self.assertRaises(SandboxError) as denied:
            self.call("repo.register", {"name": "another", "path": str(self.source)}, token=task["task_token"])
        self.assertEqual(denied.exception.code, "forbidden")
        other = self.root / "other"
        gitops.git(self.root, "clone", str(self.source), str(other))
        with self.assertRaises(SandboxError) as conflict:
            self.call("repo.register", {"name": "project", "path": str(other)})
        self.assertEqual(conflict.exception.code, "conflict")

    def test_filtered_input_and_capabilities(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        self.assertFalse((repo / ".env").exists())
        self.assertFalse((repo / "private.txt").exists())
        self.assertNotIn(b"TOP_SECRET", gitops.git(repo, "log", "-p", "--all"))
        other = self.create()
        with self.assertRaises(SandboxError) as error:
            self.call("task.read", {"task_id": other["id"], "path": "src/main.py"}, task["task_token"])
        self.assertEqual(error.exception.status, 403)
        with self.assertRaises(SandboxError):
            self.call("task.read", {"task_id": task["id"], "path": "../private.txt"}, task["task_token"])

    def test_worker_verification_install_marks_source_read_only(self):
        root = self.root / "verification-worker"
        dispatch(root, "install", {"files": {"src/main.py": {"mode": "100644", "data": encode(b"pass\n"),
            "sha256": digest(b"pass\n")}}, "limits": self.config.limits,
            "task_uid": None, "read_only_source": True})
        with self.assertRaises(SandboxError) as error:
            dispatch(root, "write", {"path": "src/main.py", "data": encode(b"changed\n"), "limit": 100})
        self.assertEqual(error.exception.code, "forbidden")

    def test_worker_repairs_controller_directory_mode_and_rejects_symlink(self):
        root = self.root / "controller-dir"
        root.mkdir()
        control = root / "control"
        control.mkdir(mode=0o755)
        control.chmod(0o755)
        dispatch(root, "install", {"files": {}, "limits": self.config.limits, "task_uid": None, "read_only_source": False})
        self.assertEqual(control.stat().st_mode & 0o777, 0o700)
        shutil.rmtree(control)
        control.symlink_to(self.root / "outside")
        with self.assertRaises(SandboxError) as error:
            dispatch(root, "install", {"files": {}, "limits": self.config.limits, "task_uid": None})
        self.assertEqual(error.exception.code, "invalid_request")

    def test_task_git_filter_does_not_inherit_controller_environment(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        marker = repo / "filter-environment.json"
        code = ("import json, os, sys; from pathlib import Path; "
                "Path('filter-environment.json').write_text(json.dumps(dict(os.environ))); "
                "sys.stdout.buffer.write(sys.stdin.buffer.read())")
        gitops.git(repo, "config", "filter.inspect.clean", shlex.join([sys.executable, "-c", code]))
        gitops.git(repo, "config", "filter.inspect.required", "true")
        (repo / "src/.gitattributes").write_text("main.py filter=inspect\n")
        self.commit(task)
        marker.unlink(missing_ok=True)
        # Force status to run the task's clean filter during result export.
        (repo / "src/main.py").write_text("answer = 9\n")
        with patch.dict("os.environ", {"CODER_AGENT_TOKEN": "private-control-token",
                        "UNRELATED_CREDENTIAL": "private-provider-key", "PYTHONPATH": "/private/controller"}):
            with self.assertRaises(SandboxError) as error:
                self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.code, "dirty_workspace")
        environment = json.loads(marker.read_text())
        self.assertNotIn("CODER_AGENT_TOKEN", environment)
        self.assertNotIn("UNRELATED_CREDENTIAL", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(environment["HOME"], str(self.client.root(task) / "home"))

    def test_end_to_end_delivery_preserves_hidden_files_and_binary(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"answer = 2\n")})
        self.call("task.write", {"task_id": task["id"], "path": "src/binary.dat", "data": encode(bytes(range(256)))})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"], "idempotency_key": "submit-once"})
        self.assertEqual(result["id"], self.call("task.submit", {"task_id": task["id"], "idempotency_key": "submit-once"})["id"])
        candidate = self.call("task.prepare_integration", {"result_id": result["id"], "target_branch": "main"})
        validation = self.call("task.validate", {"candidate_id": candidate["id"], "runtime": "python", "commands": [
            [sys.executable, "-c", "from pathlib import Path; assert Path('src/main.py').read_text() == 'answer = 2\\n'; assert Path('src/binary.dat').read_bytes() == bytes(range(256))"]]})
        verify_task = self.store_task(validation["task_id"])
        self.executions += [(verify_task["id"], i) for i in validation["execution_ids"]]
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            records = self.call("task.status", {"task_id": verify_task["id"]})["execution_records"]
            if all(r["state"] not in ("starting", "running") for r in records):
                break
            time.sleep(0.05)
        accepted = self.call("task.integrate", {"candidate_id": candidate["id"], "idempotency_key": "accept-once"})
        self.assertTrue(accepted["integrated"])
        self.assertEqual(gitops.resolve(self.source, "main"), candidate["candidate_sha"])
        self.assertEqual(gitops.git(self.source, "show", "main:private.txt"), b"private content")
        self.assertEqual(gitops.git(self.source, "show", "main:.env"), b"TOP_SECRET=should-not-be-visible\n")
        self.call("task.destroy", {"task_id": task["id"]})
        self.assertTrue(self.client.artifact("results", result["id"]).exists())
        self.assertIn(b"GIT binary patch", decode(self.call("task.result", {"result_id": result["id"]})["artifact"]["patch"]))

    def store_task(self, identifier):
        return self.client.store.get("task", identifier)

    def test_dirty_submit_rejected_and_checkpoint_recovers(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"dirty change\n")})
        with self.assertRaises(SandboxError) as error:
            self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.code, "dirty_workspace")
        checkpoint = self.call("task.checkpoint", {"task_id": task["id"]})
        self.call("task.destroy", {"task_id": task["id"], "abandon": True})
        restored = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint["id"]})
        self.assertEqual(restored["baseline_sha"], task["baseline_sha"])
        self.assertEqual(decode(self.call("task.read", {"task_id": task["id"], "path": "src/main.py"})["data"]), b"dirty change\n")

    def test_create_idempotency_and_service_restart(self):
        task = self.create("create-once")
        self.assertEqual(self.create("create-once")["id"], task["id"])
        self.assertEqual(len(self.client.store.list("task")), 1)
        execution = self.call("task.exec", {"task_id": task["id"], "argv": [sys.executable, "-c", "import time; print('before', flush=True); time.sleep(.3); print('after')"]})
        self.executions.append((task["id"], execution["execution_id"]))
        self.client = NativeClient(self.config)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            record = self.call("task.status", {"task_id": task["id"]})["execution_records"][0]
            if record["state"] == "completed":
                break
            time.sleep(0.05)
        self.assertEqual(record["exit_code"], 0)
        logs = self.call("task.logs", {"task_id": task["id"], "execution_id": execution["execution_id"]})
        self.assertEqual(decode(logs["data"]), b"before\nafter\n")

    def test_symlink_and_out_of_scope_result_rejected(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        (repo / "src/link").symlink_to(self.source / "private.txt")
        with self.assertRaises(SandboxError):
            self.call("task.read", {"task_id": task["id"], "path": "src/link"})
        (repo / "src/link").unlink()
        (repo / "unauthorized.txt").write_text("not allowed")
        self.commit(task)
        with self.assertRaises(SandboxError) as error:
            self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.status, 403)

    def test_child_cannot_expand_authorization(self):
        parent = self.create()
        request = {"repo": "project", "base": self.base, "runtime": "python", "network": "none",
            "parent_task_id": parent["id"], "files": {"include": ["**"], "exclude": []}, "ttl_minutes": 10}
        with self.assertRaises(SandboxError) as error:
            self.call("task.create", request, parent["task_token"])
        self.assertEqual(error.exception.status, 403)
        request["files"]["include"] = ["src/**"]
        child = self.call("task.create", request, parent["task_token"])
        self.assertIn("**/.env*", child["files"]["exclude"])
        with self.assertRaises(SandboxError):
            self.call("task.integrate", {"candidate_id": "anything"}, child["task_token"])

    def test_result_is_fixed_while_task_keeps_editing(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"version one\n")})
        self.commit(task)
        first = self.call("task.submit", {"task_id": task["id"]})
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"version two\n")})
        self.commit(task)
        second = self.call("task.submit", {"task_id": task["id"]})
        self.assertNotEqual(first["id"], second["id"])
        artifact = self.call("task.result", {"result_id": first["id"]})["artifact"]
        self.assertEqual(decode(artifact["files"]["src/main.py"]["data"]), b"version one\n")

    def test_submit_rejects_history_rewritten_before_task_baseline(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        gitops.git(repo, "reset", "--hard", gitops.resolve(repo, "HEAD~0"))
        # The baseline itself is valid; move to an unrelated root commit to
        # exercise the ancestry check without changing the source repository.
        gitops.git(repo, "checkout", "--orphan", "rewritten")
        (repo / "rewritten.txt").write_text("rewritten\n")
        gitops.git(repo, "add", "--all")
        gitops.git(repo, "commit", "-m", "rewritten history")
        with self.assertRaises(SandboxError) as error:
            self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.code, "history_rewritten")

    def test_rename_delete_and_executable_mode_round_trip(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        (repo / "src/main.py").rename(repo / "src/renamed.py")
        (repo / "src/run.sh").write_text("#!/bin/sh\nexit 0\n")
        (repo / "src/run.sh").chmod(0o755)
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        paths = gitops.git(self.source, "ls-tree", "-r", candidate["candidate_sha"]).decode()
        self.assertNotIn("src/main.py", paths)
        self.assertIn("src/renamed.py", paths)
        self.assertIn("100755 blob", paths)
        self.assertEqual(gitops.git(self.source, "show", candidate["candidate_sha"] + ":private.txt"), b"private content")

    def test_non_regular_and_lfs_inputs_are_explicitly_rejected(self):
        (self.source / "src/link").symlink_to("../private.txt")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "add link")
        self.base = gitops.resolve(self.source, "HEAD")
        with self.assertRaises(SandboxError):
            self.create()
        (self.source / "src/link").unlink()
        (self.source / "src/lfs.dat").write_text("version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 42\n")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "LFS pointer")
        self.base = gitops.resolve(self.source, "HEAD")
        with self.assertRaises(SandboxError):
            self.create()

    def test_checked_out_target_is_not_modified(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"answer = 2\n")})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        verification = self.call("task.validate", {"candidate_id": candidate["id"], "runtime": "python", "commands": [[sys.executable, "-c", "pass"]]})
        self.executions += [(verification["task_id"], i) for i in verification["execution_ids"]]
        self.wait_validation(verification)
        gitops.git(self.source, "checkout", "main")
        (self.source / "private.txt").write_text("user dirty work")
        with self.assertRaises(SandboxError) as error:
            self.call("task.integrate", {"candidate_id": candidate["id"]})
        self.assertEqual(error.exception.code, "checked_out_target")
        self.assertEqual((self.source / "private.txt").read_text(), "user dirty work")
        self.assertEqual(gitops.resolve(self.source, "main"), candidate["target_sha"])

    def wait_validation(self, validation):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.call("task.reconcile", {})
            current = self.client.store.get("validation", validation["id"])
            if current["state"] != "running":
                return current
            time.sleep(.05)
        self.fail("Verification did not finish")

    def test_target_advance_invalidates_verification(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"answer = 2\n")})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        validation = self.call("task.validate", {"candidate_id": candidate["id"], "runtime": "python", "commands": [[sys.executable, "-c", "pass"]]})
        self.executions += [(validation["task_id"], i) for i in validation["execution_ids"]]
        self.wait_validation(validation)
        (self.source / "concurrent.txt").write_text("another user's commit")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "concurrent update")
        advanced = gitops.resolve(self.source, "HEAD")
        gitops.git(self.source, "update-ref", "refs/heads/main", advanced, self.base)
        with self.assertRaises(SandboxError) as error:
            self.call("task.integrate", {"candidate_id": candidate["id"]})
        self.assertEqual(error.exception.code, "stale_candidate")
        self.assertEqual(gitops.resolve(self.source, "main"), advanced)

    def test_validation_commands_are_sequential_and_failure_blocks_acceptance(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"answer = 2\n")})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        validation = self.call("task.validate", {"candidate_id": candidate["id"], "runtime": "python", "commands": [
            [sys.executable, "-c", "import pathlib,time; time.sleep(.1); pathlib.Path('../build/step1').write_text('done')"],
            [sys.executable, "-c", "from pathlib import Path; assert Path('../build/step1').exists(); raise SystemExit(9)"]]})
        self.executions += [(validation["task_id"], i) for i in validation["execution_ids"]]
        self.assertEqual(self.wait_validation(validation)["state"], "failed")
        with self.assertRaises(SandboxError):
            self.call("task.integrate", {"candidate_id": candidate["id"]})

    def test_timeout_and_log_limit(self):
        self.config.limits["max_output_bytes"] = 32
        task = self.create()
        execution = self.call("task.exec", {"task_id": task["id"], "argv": [sys.executable, "-c", "import time; print('x'*100, flush=True); time.sleep(10)"], "timeout_seconds": 1})
        self.executions.append((task["id"], execution["execution_id"]))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            record = self.call("task.status", {"task_id": task["id"]})["execution_records"][0]
            if record["state"] == "timeout":
                break
            time.sleep(.05)
        self.assertEqual(record["state"], "timeout")
        self.assertTrue(record["truncated"])
        logs = self.call("task.logs", {"task_id": task["id"], "execution_id": execution["execution_id"]})
        self.assertEqual(len(decode(logs["data"])), 32)

    def test_destroy_persists_edits_after_an_earlier_submission(self):
        task = self.create()
        self.call("task.submit", {"task_id": task["id"]})
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"unsaved later edit\n")})
        destroyed = self.call("task.destroy", {"task_id": task["id"]})
        checkpoint = self.client.store.get("checkpoint", destroyed["destruction_checkpoint"])
        restored = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint["id"]})
        self.assertEqual(decode(self.call("task.read", {"task_id": task["id"], "path": "src/main.py"})["data"]), b"unsaved later edit\n")
        with self.assertRaises(SandboxError) as error:
            self.call("task.status", {"task_id": task["id"]}, task["task_token"])
        self.assertEqual(error.exception.status, 401)

    def test_task_token_can_retrieve_persisted_result_after_destroy_until_expiry(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"saved\n")})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        self.call("task.destroy", {"task_id": task["id"]})
        user_result = self.call("task.result", {"result_id": result["id"]}, task["task_token"])
        self.assertEqual(decode(user_result["artifact"]["files"]["src/main.py"]["data"]), b"saved\n")
        self.assertEqual(self.call("task.status", {"task_id": task["id"]}, task["task_token"])["environment_state"], "destroyed")
        with self.assertRaises(SandboxError) as error:
            self.call("task.read", {"task_id": task["id"], "path": "src/main.py"}, task["task_token"])
        self.assertEqual(error.exception.code, "not_ready")

    def test_timeout_still_applies_after_command_closes_stdout(self):
        task = self.create()
        execution = self.call("task.exec", {"task_id": task["id"], "argv": [sys.executable, "-c",
             "import os,time; os.close(1); os.close(2); time.sleep(10)"], "timeout_seconds": 1})
        self.executions.append((task["id"], execution["execution_id"]))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            record = self.call("task.status", {"task_id": task["id"]})["execution_records"][0]
            if record["state"] not in ("starting", "running"):
                break
            time.sleep(.05)
        self.assertEqual(record["state"], "timeout")

    def test_expiry_reclaims_environment_and_preserves_dirty_checkpoint(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"at expiry\n")})
        record = self.store_task(task["id"])
        record["expires_at"] = time.time() - 1
        self.client.store.put("task", record)
        self.call("task.reconcile", {})
        expired = self.store_task(task["id"])
        self.assertEqual(expired["environment_state"], "expired")
        self.assertFalse(self.client.exists(expired))
        self.call("task.restore", {"task_id": task["id"], "checkpoint_id": expired["expiry_checkpoint"]})
        self.assertEqual(decode(self.call("task.read", {"task_id": task["id"], "path": "src/main.py"})["data"]), b"at expiry\n")


    def test_file_directory_transitions_are_delivered(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        (repo / "src/main.py").unlink()
        (repo / "src/main.py").mkdir()
        (repo / "src/main.py/nested.py").write_text("nested = True\n")
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        prepared = self.call("task.prepare_integration", {"result_id": result["id"]})
        self.assertEqual(gitops.git(self.source, "show", prepared["candidate_sha"] + ":src/main.py/nested.py"), b"nested = True\n")

    def test_checkpoint_restore_handles_file_directory_transitions_both_directions(self):
        task = self.create()
        repo = self.client.root(task) / "repo"
        (repo / "src/main.py").unlink()
        (repo / "src/main.py").mkdir()
        (repo / "src/main.py/nested.py").write_text("nested\n")
        checkpoint = self.call("task.checkpoint", {"task_id": task["id"]})
        self.call("task.destroy", {"task_id": task["id"], "abandon": True})
        restored_task = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint["id"]})
        restored = self.client.root(self.store_task(restored_task["id"])) / "repo"
        self.assertEqual((restored / "src/main.py/nested.py").read_text(), "nested\n")
        # Turn the directory back into a regular file and restore again.
        shutil.rmtree(restored / "src/main.py")
        (restored / "src/main.py").write_text("regular\n")
        checkpoint2 = self.call("task.checkpoint", {"task_id": task["id"]})
        self.call("task.destroy", {"task_id": task["id"], "abandon": True})
        restored_task = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint2["id"]})
        restored = self.client.root(self.store_task(restored_task["id"])) / "repo"
        self.assertEqual((restored / "src/main.py").read_text(), "regular\n")

    def test_linked_worktree_branch_is_supported_as_snapshot_source(self):
        linked = self.root / "linked"
        gitops.git(self.source, "worktree", "add", "-b", "task/linked", str(linked), self.base)
        (linked / "src/main.py").write_text("answer = 42\n")
        gitops.git(linked, "add", "--all")
        gitops.git(linked, "commit", "-m", "worktree branch change")
        self.config.repos["project"] = linked
        task = self.call("task.create", {"repo": "project", "base": "task/linked", "runtime": "python",
             "files": {"include": ["src/**"], "exclude": []}})
        task_repo = self.client.root(task) / "repo"
        self.assertTrue((linked / ".git").is_file())
        self.assertTrue((task_repo / ".git").is_dir())
        self.assertEqual((task_repo / "src/main.py").read_text(), "answer = 42\n")
        self.assertNotEqual(task["baseline_sha"], gitops.resolve(linked, "HEAD"))
        self.assertFalse((task_repo / ".git/objects/info/alternates").exists())
        self.assertEqual(gitops.git(self.source, "show", "main:src/main.py"), b"answer = 1\n")

    def test_repository_mode_installs_independent_history_bundle(self):
        task = self.call("task.create", {"repo": "project", "base": self.base,
            "workspace_mode": "repository", "runtime": "python", "network": "none",
            "files": {"include": ["src/**"], "exclude": ["**/.env*"]},
            "purpose": "investigate history"})
        repo = self.client.root(task) / "repo"
        self.assertTrue((repo / ".git").is_dir())
        self.assertFalse((repo / ".git/objects/info/alternates").exists())
        self.assertEqual(gitops.resolve(repo, "HEAD"), self.base)
        self.assertEqual(gitops.git(repo, "rev-list", "--count", "HEAD").decode().strip(), "1")
        with self.assertRaises(SandboxError):
            self.call("task.read", {"task_id": task["id"], "path": ".env"}, task["task_token"])
        execution = self.call("task.exec", {"task_id": task["id"], "argv": ["git", "show", "HEAD:.env"],
            "idempotency_key": "history-secret"})
        self.executions.append((task["id"], execution["execution_id"]))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            record = self.call("task.status", {"task_id": task["id"]})["execution_records"][0]
            if record["state"] not in ("starting", "running"):
                break
            time.sleep(.05)
        self.assertEqual(record["exit_code"], 0)
        logs = self.call("task.logs", {"task_id": task["id"], "execution_id": execution["execution_id"]}, task["task_token"])
        self.assertIn(b"TOP_SECRET", decode(logs["data"]))
        (repo / "src/main.py").write_text("answer = 9\n")
        gitops.git(repo, "add", "--all")
        gitops.git(repo, "commit", "-m", "history task change")
        first = gitops.resolve(repo, "HEAD")
        gitops.git(repo, "-c", "user.name=History Agent", "commit", "--allow-empty", "-m", "second task commit")
        head = gitops.resolve(repo, "HEAD")
        result = self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(result["base"], self.base)
        self.assertEqual(result["result_sha"], head)
        # Later commits must not alter this frozen bundle or incoming version.
        (repo / "src/main.py").write_text("answer = 10\n")
        self.commit(task)
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        self.assertEqual(candidate["incoming_sha"], head)
        self.assertEqual(gitops.resolve(self.source, head + "^"), first)
        self.assertEqual(gitops.git(self.source, "show", "--no-patch", "--format=%an", head).strip(), b"History Agent")
        self.assertEqual(gitops.git(self.source, "show", candidate["candidate_sha"] + ":src/main.py"), b"answer = 9\n")

    def test_repository_worktree_input_excludes_unrelated_refs_and_objects(self):
        gitops.git(self.source, "checkout", "-b", "unrelated", self.base)
        (self.source / "only-other-branch.txt").write_text("unrelated branch content\n")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "unrelated branch commit")
        unrelated = gitops.resolve(self.source, "HEAD")
        gitops.git(self.source, "tag", "unrelated-tag", unrelated)
        linked = self.root / "linked-repository"
        gitops.git(self.source, "worktree", "add", "-b", "task/local-only", str(linked), self.base)
        (linked / "src/main.py").write_text("answer = 42\n")
        gitops.git(linked, "add", "--all")
        gitops.git(linked, "commit", "-m", "unpublished worktree commit")
        branch_sha = gitops.resolve(linked, "HEAD")
        self.config.repos["project"] = linked
        task = self.call("task.create", {"repo": "project", "base": "task/local-only", "runtime": "python",
            "workspace_mode": "repository", "files": {"include": ["src/**"], "exclude": []}})
        repo = self.client.root(task) / "repo"
        self.assertTrue((linked / ".git").is_file())
        self.assertTrue((repo / ".git").is_dir())
        self.assertEqual(gitops.resolve(repo, "HEAD"), branch_sha)
        self.assertEqual(gitops.git(repo, "rev-list", "--count", "HEAD").strip(), b"2")
        self.assertEqual(gitops.git(repo, "tag", "--list"), b"")
        with self.assertRaises(SandboxError):
            gitops.git(repo, "cat-file", "-e", unrelated)
        (repo / "src/main.py").write_text("sandbox-only change\n")
        self.assertEqual((linked / "src/main.py").read_text(), "answer = 42\n")
        self.assertFalse((repo / ".git/objects/info/alternates").exists())

    def repository_task(self):
        return self.call("task.create", {"repo": "project", "base": self.base, "runtime": "python",
            "workspace_mode": "repository", "files": {"include": ["src/**"], "exclude": ["**/.env*"]}})

    def test_repository_rejects_unauthorized_intermediate_commit(self):
        task = self.repository_task()
        repo = self.client.root(task) / "repo"
        original = (repo / "private.txt").read_bytes()
        (repo / "private.txt").write_text("unauthorized intermediate change\n")
        self.commit(task)
        unauthorized = gitops.resolve(repo, "HEAD")
        (repo / "private.txt").write_bytes(original)
        (repo / "src/main.py").write_text("answer = 2\n")
        self.commit(task)
        with self.assertRaises(SandboxError) as error:
            self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.code, "forbidden")
        self.assertEqual(self.client.store.list("result"), [])
        self.assertEqual(gitops.resolve(self.source, "main"), self.base)
        self.assertEqual(gitops.git(self.source, "for-each-ref", "--format=%(refname)", "refs/heads/incoming/"), b"")
        with self.assertRaises(SandboxError):
            gitops.git(self.source, "cat-file", "-e", unauthorized)

    def test_repository_merge_history_is_explicitly_rejected(self):
        task = self.repository_task()
        repo = self.client.root(task) / "repo"
        (repo / "src/left.py").write_text("left = True\n")
        self.commit(task)
        gitops.git(repo, "checkout", "-b", "side", self.base)
        (repo / "src/right.py").write_text("right = True\n")
        self.commit(task)
        gitops.git(repo, "checkout", "task")
        gitops.git(repo, "merge", "--no-ff", "side", "-m", "merge side")
        with self.assertRaises(SandboxError) as error:
            self.call("task.submit", {"task_id": task["id"]})
        self.assertEqual(error.exception.code, "unsupported_history")
        self.assertEqual(self.client.store.list("result"), [])

    def test_repository_checkpoint_preserves_commits_and_dirty_files(self):
        task = self.repository_task()
        repo = self.client.root(task) / "repo"
        (repo / "src/main.py").write_text("answer = 2\n")
        self.commit(task)
        gitops.git(repo, "commit", "--allow-empty", "-m", "checkpoint second commit")
        head = gitops.resolve(repo, "HEAD")
        (repo / "src/main.py").write_text("dirty after commit\n")
        checkpoint = self.call("task.checkpoint", {"task_id": task["id"]})
        self.call("task.destroy", {"task_id": task["id"], "abandon": True})
        restored = self.call("task.restore", {"task_id": task["id"], "checkpoint_id": checkpoint["id"]})
        restored_repo = self.client.root(restored) / "repo"
        self.assertEqual(gitops.resolve(restored_repo, "HEAD"), head)
        self.assertEqual((restored_repo / "src/main.py").read_text(), "dirty after commit\n")
        self.assertEqual((restored_repo / "private.txt").read_text(), "private content")
        self.assertEqual(gitops.git(restored_repo, "rev-list", "--count", "HEAD").strip(), b"3")
        with self.assertRaises(SandboxError):
            self.call("task.status", {"task_id": task["id"]}, task["task_token"])
        self.commit(restored)
        result = self.call("task.submit", {"task_id": task["id"]})
        candidate = self.call("task.prepare_integration", {"result_id": result["id"]})
        self.assertEqual(candidate["incoming_sha"], result["result_sha"])

    def test_merge_conflict_does_not_update_target(self):
        task = self.create()
        self.call("task.write", {"task_id": task["id"], "path": "src/main.py", "data": encode(b"task edit\n")})
        self.commit(task)
        result = self.call("task.submit", {"task_id": task["id"]})
        (self.source / "src/main.py").write_text("conflicting target edit\n")
        gitops.git(self.source, "add", "--all")
        gitops.git(self.source, "commit", "-m", "concurrent conflicting change")
        advanced = gitops.resolve(self.source, "HEAD")
        gitops.git(self.source, "update-ref", "refs/heads/main", advanced, self.base)
        with self.assertRaises(SandboxError) as error:
            self.call("task.prepare_integration", {"result_id": result["id"]})
        self.assertEqual(error.exception.code, "merge_conflict")
        self.assertEqual(gitops.resolve(self.source, "main"), advanced)

    def test_ambiguous_supervisor_launch_is_not_replayed(self):
        task = self.create()
        record = {"id": "eambiguous", "argv": [sys.executable, "-c", "raise SystemExit(99)"],
                  "state": "starting", "launch_pending": True, "created_at": time.time()}
        atomic_write(self.client.root(task) / "control/executions" / (record["id"] + ".json"), json.dumps(record).encode())
        stored = self.store_task(task["id"])
        stored["executions"].append(record["id"])
        self.client.store.put("task", stored)
        self.client.persist_execution(stored, record)
        status = self.call("task.status", {"task_id": task["id"]})
        self.assertEqual(status["execution_records"][0]["state"], "lost")


if __name__ == "__main__":
    unittest.main()
