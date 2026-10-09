"""Install the built Rust product, user LaunchAgent and user MCP registrations."""
import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import subprocess
import sys
import time

LABEL = "dev.agenticsandbox.controller"


def register_dsh(home, data, bridge, backups):
    command = shutil.which("dsh")
    if not command:
        return False
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Installed DSH requires Node.js to validate its global patch")
    package = Path(command).resolve().parents[1] / "package.json"
    patch = home / ".dsh/cordis.patch.yml"
    existing = patch.read_text() if patch.exists() else ""
    entry = {"id": "mcp-agenticsandbox", "name": "@deepseek-ai/dsh-mcp-client", "config": {
        "serverName": "agenticsandbox", "transport": "stdio", "command": bridge[0],
        "args": bridge[1:], "cwd": str(data), "toolCallTimeoutMs": 120000, "failOnStartupError": True}}
    # Parse without evaluating tags. Preserve all existing YAML and plugin entries.
    script = r'''
const fs = require('node:fs');
const {createRequire} = require('node:module');
const {isDeepStrictEqual} = require('node:util');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const YAML = createRequire(input.package)('yaml');
function parse(text) {
  const doc = YAML.parseDocument(text);
  if (doc.errors.length || !YAML.isSeq(doc.contents)) throw Error('DSH home patch must be one valid YAML sequence');
  return doc.toJS();
}
const rows = input.text.trim() ? parse(input.text) : [];
const entries = rows.flatMap(row => Array.isArray(row.insert) ? row.insert : []);
const matches = entries.filter(row => row.id === input.entry.id || row.config?.serverName === 'agenticsandbox');
if (matches.length) {
  if (matches.length !== 1 || matches[0].id !== input.entry.id || matches[0].name !== input.entry.name || !isDeepStrictEqual(matches[0].config, input.entry.config))
    throw Error('Existing DSH agenticsandbox registration differs; refusing to replace it');
  process.stdout.write(JSON.stringify({changed:false}));
} else {
  const text = input.text + (input.text && !input.text.endsWith('\n') ? '\n' : '') + YAML.stringify([{insert:[input.entry]}]);
  parse(text);
  process.stdout.write(JSON.stringify({changed:true,text}));
}
'''
    result = subprocess.run([node, "-e", script], input=json.dumps({"package": str(package),
        "text": existing, "entry": entry}).encode(), capture_output=True, check=True)
    update = json.loads(result.stdout)
    if update["changed"]:
        if patch.exists():
            target = backups / "cordis.patch.yml.dsh"
            target.write_bytes(patch.read_bytes())
            target.chmod(0o600)
        private_write(patch, update["text"].encode())
    return True


def private_write(path, data, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".installing")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    temp.replace(path)
    path.chmod(mode)


def install(args):
    if sys.platform != "darwin":
        raise RuntimeError("This installer requires macOS")
    home = Path.home()
    data = home / ".local/share/agenticsandbox"
    binary = home / ".local/bin/agenticsandbox"
    config = data / "config.json"
    state = data / "state"
    token = state / "admin.token"
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backups = data / "backups" / timestamp
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    url = "http://127.0.0.1:" + str(args.port)
    bridge = [str(binary), "mcp", "--url", url, "--token-file", str(token)]
    if args.dsh_only:
        if not binary.is_file() or not token.is_file():
            raise RuntimeError("Install the native controller before registering DSH")
        if not register_dsh(home, data, bridge, backups):
            raise RuntimeError("DSH is not installed")
        print(json.dumps({"registered_clients": ["dsh"], "patch": str(home / ".dsh/cordis.patch.yml"),
            "controller": url, "backups": str(backups)}, indent=2))
        return
    if args.binary is None or args.config is None:
        raise RuntimeError("Full installation requires --binary and --config")
    for path in [binary, config, home / ".codex/config.toml", home / ".claude.json", home / "Library/LaunchAgents" / (LABEL + ".plist")]:
        if path.exists():
            target = backups / (path.name + (".codex" if path.parent.name == ".codex" else ""))
            target.write_bytes(path.read_bytes())
            target.chmod(0o600)
    if config.exists():
        cfg = json.loads(config.read_text())
        if cfg.get("backend") != "remote":
            raise RuntimeError("Existing installation uses a different backend; refusing to overwrite")
    else:
        cfg = json.loads(args.config.read_text())
        cfg["state_dir"] = str(state)
        cfg["admin_token_file"] = str(token)
    private_write(binary, args.binary.read_bytes(), 0o700)
    private_write(config, json.dumps(cfg, indent=2).encode() + b"\n")
    subprocess.run([str(binary), "init", "--config", str(config)], check=True, capture_output=True)
    port = args.port
    plist = home / "Library/LaunchAgents" / (LABEL + ".plist")
    private_write(plist, plistlib.dumps({"Label": LABEL,
        "ProgramArguments": [str(binary), "serve", "--config", str(config), "--host", "127.0.0.1", "--port", str(port)],
        "WorkingDirectory": str(data), "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
        "StandardOutPath": str(data / "controller.stdout.log"), "StandardErrorPath": str(data / "controller.stderr.log"),
        "EnvironmentVariables": {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}}))
    domain = "gui/" + str(os.getuid())
    subprocess.run(["/bin/launchctl", "bootout", domain + "/" + LABEL], capture_output=True)
    subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)], check=True)
    deadline = time.monotonic() + 20
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.5):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Installed controller did not start; inspect " + str(data / "controller.stderr.log"))
            time.sleep(.2)
    subprocess.run([str(binary), "call", "sandbox.info", "--url", url, "--token-file", str(token)], input=b"{}", capture_output=True, check=True)
    registered = []
    for cli, prefix in [("codex", ["mcp", "add", "agenticsandbox", "--"]), ("claude", ["mcp", "add", "--scope", "user", "agenticsandbox", "--"])]:
        command = shutil.which(cli)
        if not command:
            continue
        if cli == "claude":
            # Replace only this named user registration, never other servers.
            subprocess.run([command, "mcp", "remove", "--scope", "user", "agenticsandbox"], capture_output=True)
        subprocess.run([command, *prefix, *bridge], check=True, capture_output=True)
        registered.append(cli)
    if register_dsh(home, data, bridge, backups):
        registered.append("dsh")
    print(json.dumps({"binary": str(binary), "config": str(config), "controller": url,
        "launch_agent": str(plist), "registered_clients": registered, "backups": str(backups)}, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path)
    p.add_argument("--config", type=Path, help="Prepared SSH Docker config for a first install")
    p.add_argument("--dsh-only", action="store_true", help="Register installed controller in DSH without restarting it")
    p.add_argument("--port", type=int, default=18765)
    install(p.parse_args())
