"""Create a reproducible public Rust runtime/development bundle."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def source_names(root=ROOT, development=False):
    root = Path(root)
    names = ["Cargo.toml", "Cargo.lock", "build.rs", ".dockerignore", "runtime/Dockerfile", "runtime/entrypoint.sh"]
    names += [str(p.relative_to(root)) for p in sorted((root / "src").rglob("*")) if p.suffix in (".rs", ".json")]
    if development:
        for folder in ("tests", "scripts"):
            names += [str(p.relative_to(root)) for p in sorted((root / folder).rglob("*.py"))]
    return sorted(set(names))


def bundle(output, development=False, root=ROOT):
    root = Path(root)
    names = source_names(root, development)
    files = {}
    for name in sorted(set(names)):
        path = root / name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("Bundle refuses symlinks: " + name)
        files[name] = path.read_bytes()
    source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()
                     if name in ("Cargo.toml", "Cargo.lock", "build.rs") or name.startswith("src/")}
    source_sha = hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    files["build-context-manifest.json"] = json.dumps({"schema_version": 2, "implementation": "rust", "worker_protocol_version": 1,
        "worker_source_sha256": source_sha,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}},
        sort_keys=True, separators=(",", ":")).encode() + b"\n"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name.endswith("entrypoint.sh") else 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    output.write_bytes(buf.getvalue())
    output.chmod(0o600)
    return {"bundle_sha256": hashlib.sha256(buf.getvalue()).hexdigest(), "implementation": "rust",
            "worker_protocol_version": 1, "worker_source_sha256": source_sha, "source_files": len(files) - 1}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(json.dumps({"bundle": str(args.output), **bundle(args.output, args.development)}, indent=2))
