"""Serialization and file helpers for synthetic audit inputs and reports."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile


class SandboxError(RuntimeError):
    def __init__(self, message, code="invalid_request", status=400):
        super().__init__(message)
        self.code, self.status = code, status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            os.fchmod(temporary.fileno(), mode)
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
