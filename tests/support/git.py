"""Create and inspect synthetic Git repositories in acceptance tests."""
import os
import subprocess
from .json_helpers import SandboxError


def git(repo, *args, data=None):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
    command = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
               "-c", "commit.gpgsign=false", "-c", "safe.directory=*",
               "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
               "-C", str(repo), *args]
    result = subprocess.run(command, input=data, capture_output=True, env=environment, timeout=60)
    if result.returncode:
        raise SandboxError(result.stderr.decode(errors="replace"), "git_error", 409)
    return result.stdout


def resolve(repo, revision):
    return git(repo, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
