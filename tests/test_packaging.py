"""Public native bundles must be complete, deterministic and credential-free."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from support.json_helpers import canonical, digest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime_package", ROOT / "scripts/package-runtime.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenticsandbox-package-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        for name in package.source_names(ROOT, development=True):
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

    def test_development_bundle_discovers_native_tests_without_legacy_product(self):
        for name in (".state/admin.token", "config.json", ".env", "runtime/.coder/session", "src/private.py"):
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("private fixture")
        output = self.root / "development.tar.gz"
        report = package.bundle(output, development=True, root=self.source)
        extracted = self.root / "extracted"
        with tarfile.open(output) as archive:
            names = set(archive.getnames())
            self.assertIn("src/main.rs", names)
            self.assertIn("scripts/protocol-acceptance.py", names)
            self.assertIn("tests/support/native.py", names)
            self.assertNotIn("pyproject.toml", names)
            self.assertFalse(any(name.startswith(("rust/", "src/agenticsandbox/")) for name in names))
            self.assertFalse(names & {".state/admin.token", "config.json", ".env", "runtime/.coder/session", "src/private.py"})
            for member in archive:
                self.assertTrue(member.isfile())
                target = extracted / member.name
                self.assertTrue(target.resolve().is_relative_to(extracted.resolve()))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        manifest = json.loads((extracted / "build-context-manifest.json").read_text())
        for name, checksum in manifest["files"].items():
            self.assertEqual(checksum, digest((extracted / name).read_bytes()))
        native = {name: checksum for name, checksum in manifest["files"].items()
                  if name in ("Cargo.toml", "Cargo.lock", "build.rs") or name.startswith("src/")}
        self.assertEqual(report["worker_source_sha256"], digest(canonical(native)))
        result = subprocess.run([sys.executable, "-c",
            "import unittest; loader=unittest.TestLoader(); suite=loader.discover('tests'); "
            "assert not loader.errors, loader.errors; assert suite.countTestCases() >= 50"],
            cwd=extracted, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_runtime_bundle_contains_only_native_build_inputs(self):
        output = self.root / "runtime.tar.gz"
        package.bundle(output, root=self.source)
        with tarfile.open(output) as archive:
            names = archive.getnames()
        self.assertIn("Cargo.lock", names)
        self.assertIn("src/worker.rs", names)
        self.assertFalse(any(name.startswith(("scripts/", "tests/")) or name.endswith(".py") for name in names))

    def test_archive_is_reproducible_and_audit_changes_affect_manifest(self):
        first, second = self.root / "first.tar.gz", self.root / "second.tar.gz"
        before = package.bundle(first, development=True, root=self.source)
        script = self.source / "scripts/docker-runtime-audit.py"
        os.utime(script, (1, 1))
        package.bundle(second, development=True, root=self.source)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        script.write_bytes(script.read_bytes() + b"\n# modified fixture\n")
        after = package.bundle(second, development=True, root=self.source)
        self.assertNotEqual(before["bundle_sha256"], after["bundle_sha256"])
        self.assertEqual(before["worker_source_sha256"], after["worker_source_sha256"])

    def test_symlink_cannot_include_an_external_private_file(self):
        secret = self.root / "private.txt"
        secret.write_text("private fixture")
        (self.source / "src/leak.rs").symlink_to(secret)
        output = self.root / "runtime.tar.gz"
        with self.assertRaisesRegex(ValueError, "refuses symlinks"):
            package.bundle(output, root=self.source)
        self.assertFalse(output.exists())
