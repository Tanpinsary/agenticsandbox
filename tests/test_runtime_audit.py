import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock

from support.json_helpers import canonical


spec = importlib.util.spec_from_file_location("docker_runtime_audit",
    Path(__file__).resolve().parents[1] / "scripts/docker-runtime-audit.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AuditCleanupTest(unittest.TestCase):
    def test_cleanup_only_removes_containers_with_this_audit_label(self):
        audit = module.DockerAudit("sha256:" + "a" * 64)
        audit.containers = ["owned-test", "unrelated-container"]
        unrelated = {"Config": {"Labels": {"agenticsandbox.audit": "another-run"}}}
        owned = {"Config": {"Labels": {"agenticsandbox.audit": audit.run_id}}}
        audit.docker = Mock(side_effect=[canonical([unrelated]), canonical([owned]), b""])
        self.assertTrue(audit.cleanup())
        self.assertEqual(audit.docker.call_args_list[-1].args, ("rm", "--force", "owned-test"))
        self.assertFalse(any(call.args[0] == "rm" and call.args[-1] == "unrelated-container"
                             for call in audit.docker.call_args_list))

    def test_unobservable_containers_are_not_deleted_and_cleanup_is_incomplete(self):
        audit = module.DockerAudit("sha256:" + "a" * 64)
        audit.containers = ["unobservable"]
        audit.docker = Mock(side_effect=RuntimeError("Docker inspection failed"))
        self.assertFalse(audit.cleanup())
        audit.docker.assert_called_once_with("inspect", "unobservable")
