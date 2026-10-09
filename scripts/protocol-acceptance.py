"""Run all protocol and audit regressions against the native Rust CLI.

Python supplies fixtures and assertions only. Every controller and detached
worker operation runs in the Rust executable, including after a CLI restart.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from support.json_helpers import atomic_write, canonical, digest
from support import native
import test_delivery as delivery

BINARY = native.BINARY


class AcceptanceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []
        self.passed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


def source_snapshot():
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("runtime_package", ROOT / "scripts/package-runtime.py")
    package = module_from_spec(spec)
    spec.loader.exec_module(package)
    return {name: digest((ROOT / name).read_bytes()) for name in package.source_names(ROOT, development=True)}


def main():
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=BINARY)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append")
    parser.add_argument("--transport-only", action="store_true")
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    native.BINARY = BINARY
    os.environ["AGENTICSANDBOX_TEST_BINARY"] = str(BINARY)
    sources = source_snapshot()
    binary_sha = digest(BINARY.read_bytes())
    worker_identity = json.loads(subprocess.check_output([str(BINARY), "worker"],
        input=canonical({"root": "/tmp", "operation": "identity", "request": {}})))["result"]
    native_sources = {name: value for name, value in sources.items()
                      if name in ("Cargo.toml", "Cargo.lock", "build.rs") or name.startswith("src/")}
    binary_matches_sources = (worker_identity.get("implementation") == "rust"
        and worker_identity.get("worker_source_sha256") == digest(canonical(native_sources)))
    if args.case:
        suite = unittest.TestSuite(delivery.DeliveryTest("test_" + name) for name in args.case)
    elif args.transport_only:
        suite = unittest.defaultTestLoader.loadTestsFromName("test_transport.TransportTest")
    else:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    import test_transport
    test_transport.BINARY = BINARY
    start = time.monotonic()
    expected_tests = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2, resultclass=AcceptanceResult).run(suite)
    sources_unchanged = sources == source_snapshot()
    binary_unchanged = binary_sha == digest(BINARY.read_bytes())
    passed = (result.wasSuccessful() and result.testsRun == expected_tests and expected_tests > 0
              and not result.skipped and not result.expectedFailures and sources_unchanged
              and binary_unchanged and binary_matches_sources)
    report = {"schema_version": 2, "implementation": "rust", "binary_sha256": binary_sha,
              "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "platform": platform.system(), "python": platform.python_version(),
              "scope": "selected_cases" if args.case else "transport" if args.transport_only else "full_protocol",
              "worker_source_sha256": worker_identity["worker_source_sha256"],
              "source_files": sources, "source_sha256": digest(canonical(sources)),
              "sources_unchanged": sources_unchanged, "binary_unchanged": binary_unchanged,
              "binary_matches_sources": binary_matches_sources,
              "expected_tests": expected_tests, "executed_tests": result.executed, "passed_tests": result.passed,
              "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "elapsed_seconds": time.monotonic() - start,
              "failure_tests": [test.id() for test, _ in result.failures],
              "error_tests": [test.id() for test, _ in result.errors],
              "skipped_tests": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
              "expected_failures": [test.id() for test, _ in result.expectedFailures],
              "passed": bool(passed), "production_approved": False, "os_isolation": False}
    if args.output:
        atomic_write(args.output, canonical(report) + b"\n")
    print(json.dumps({key: value for key, value in report.items()
        if key not in ("source_files", "executed_tests", "passed_tests")}, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
