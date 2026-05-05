from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..scanner import is_extension_manifest, normalize_archive_member_path, scan_target
from .canary import create_canary_workspace
from .models import DynamicEvent, DynamicRunReport, DynamicViolation


@dataclass(frozen=True)
class DynamicRunOptions:
    timeout: int = 10
    keep_run: bool = False
    run_root: Path | None = None
    node: str = "node"


def run_extension(target: str | Path, options: DynamicRunOptions | None = None) -> DynamicRunReport:
    options = options or DynamicRunOptions()
    if options.timeout <= 0:
        raise ValueError("dynamic run timeout must be positive")
    target_path = Path(target).expanduser()
    scan = scan_target(target_path)

    if options.keep_run:
        run_dir = _persistent_run_dir(options.run_root)
        return _run_in_directory(target_path, scan, options, run_dir)

    with tempfile.TemporaryDirectory(prefix="red-widow-run-") as temp_dir:
        report = _run_in_directory(target_path, scan, options, Path(temp_dir))
        return report


def _run_in_directory(
    target_path: Path,
    scan: Any,
    options: DynamicRunOptions,
    run_dir: Path,
) -> DynamicRunReport:
    run_dir.mkdir(parents=True, exist_ok=True)
    extension_dir = _prepare_extension(target_path, run_dir)
    manifest = _load_manifest(extension_dir)
    workspace = create_canary_workspace(run_dir / "workspace")
    report = DynamicRunReport(
        target=str(target_path),
        scan=scan,
        run_dir=str(run_dir),
        workspace_dir=str(workspace.root),
        extension_dir=str(extension_dir),
        canary_marker=workspace.marker,
    )

    main = manifest.get("main")
    if not isinstance(main, str) or not main:
        report.errors.append("extension manifest has no JavaScript main entry point")
        return report

    main_path = (extension_dir / main).resolve(strict=False)
    try:
        main_path.relative_to(extension_dir.resolve(strict=True))
    except ValueError:
        report.errors.append(f"extension main escapes package root: {main}")
        return report
    if not main_path.is_file():
        report.errors.append(f"extension main does not exist: {main}")
        return report

    harness_output = run_dir / "harness-report.json"
    args = [
        options.node,
        str(Path(__file__).with_name("harness.js")),
        json.dumps(
            {
                "extensionRoot": str(extension_dir),
                "mainPath": str(main_path),
                "workspaceRoot": str(workspace.root),
                "marker": workspace.marker,
                "reportPath": str(harness_output),
                "manifest": manifest,
            }
        ),
    ]
    try:
        completed = subprocess.run(
            args,
            cwd=workspace.root,
            capture_output=True,
            text=True,
            timeout=options.timeout,
            check=False,
        )
    except FileNotFoundError:
        report.errors.append(f"node executable not found: {options.node}")
        return report
    except subprocess.TimeoutExpired as exc:
        report.timed_out = True
        report.errors.append(f"harness timed out after {options.timeout}s")
        if exc.stdout:
            (run_dir / "harness.stdout").write_text(str(exc.stdout), encoding="utf-8")
        if exc.stderr:
            (run_dir / "harness.stderr").write_text(str(exc.stderr), encoding="utf-8")
        report.violations = _violations_from_events(report.events, report.errors)
        return report

    report.harness_exit_code = completed.returncode
    (run_dir / "harness.stdout").write_text(completed.stdout, encoding="utf-8")
    (run_dir / "harness.stderr").write_text(completed.stderr, encoding="utf-8")

    if harness_output.is_file():
        try:
            payload = json.loads(harness_output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            report.errors.append(f"harness report is invalid JSON: {exc}")
        else:
            report.events = [
                DynamicEvent.from_dict(event)
                for event in payload.get("events", [])
                if isinstance(event, dict)
            ]
            errors = payload.get("errors", [])
            if isinstance(errors, list):
                report.errors.extend(str(error) for error in errors)
    else:
        report.errors.append("harness did not write a report")
    if completed.returncode != 0:
        report.errors.append(f"harness exited with status {completed.returncode}")

    report.violations = _violations_from_events(report.events, report.errors)
    return report


def _prepare_extension(target: Path, run_dir: Path) -> Path:
    if target.is_dir():
        destination = run_dir / "extension"
        shutil.copytree(target, destination, symlinks=True)
        return _find_extension_root(destination)
    if zipfile.is_zipfile(target):
        destination = run_dir / "package"
        destination.mkdir(parents=True, exist_ok=True)
        seen_paths: set[str] = set()
        with zipfile.ZipFile(target) as archive:
            for member in archive.infolist():
                _extract_member_safely(archive, member, destination, seen_paths)
        return _find_extension_root(destination)
    raise ValueError(f"target is neither a directory nor a VSIX/ZIP package: {target}")


def _extract_member_safely(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    destination: Path,
    seen_paths: set[str],
) -> None:
    member_path = normalize_archive_member_path(member.filename)
    if member.is_dir():
        return
    if member_path in seen_paths:
        raise ValueError(f"duplicate path in VSIX archive: {member_path}")
    seen_paths.add(member_path)
    output_path = destination / member_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(member, "r") as source, output_path.open("wb") as output:
        shutil.copyfileobj(source, output)


def _find_extension_root(root: Path) -> Path:
    candidates = sorted(
        root.rglob("package.json"),
        key=lambda path: (path.as_posix() != (root / "extension" / "package.json").as_posix(), len(path.parts), path.as_posix()),
    )
    for candidate in candidates:
        if candidate.is_symlink():
            continue
        with suppress(OSError, json.JSONDecodeError):
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            if is_extension_manifest(payload):
                return candidate.parent
    raise ValueError("could not find a VS Code extension package.json manifest")


def _load_manifest(extension_dir: Path) -> dict[str, Any]:
    payload = json.loads((extension_dir / "package.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("extension package.json is not an object")
    return payload


def _persistent_run_dir(run_root: Path | None) -> Path:
    root = run_root or Path(".red-widow") / "runs"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = 0
    while True:
        name = f"rw-{stamp}" if suffix == 0 else f"rw-{stamp}-{suffix}"
        candidate = root / name
        if not candidate.exists():
            candidate.mkdir(parents=True)
            return candidate
        suffix += 1


def _violations_from_events(
    events: list[DynamicEvent],
    errors: list[str],
) -> list[DynamicViolation]:
    violations: list[DynamicViolation] = []
    seen: set[tuple[str, str]] = set()

    def add(
        rule_id: str,
        title: str,
        severity: str,
        detail: str,
        evidence: str,
        blocking: bool,
    ) -> None:
        key = (rule_id, evidence)
        if key in seen:
            return
        seen.add(key)
        violations.append(
            DynamicViolation(
                rule_id=rule_id,
                title=title,
                severity=severity,
                detail=detail,
                evidence=(evidence,),
                blocking=blocking,
            )
        )

    for event in events:
        evidence = _event_evidence(event)
        if event.kind == "fs" and event.canary and event.operation.startswith("read"):
            add(
                "canary-file-read",
                "Extension read a canary secret file",
                "high",
                "extension accessed sandbox credential material during activation or command execution",
                evidence,
                True,
            )
        elif event.kind in {"fetch", "http", "https", "net", "tls"} and event.canary:
            add(
                "canary-exfiltration",
                "Extension attempted to exfiltrate a canary marker",
                "critical",
                "outbound traffic contained Red Widow canary material and was blocked by the harness",
                evidence,
                True,
            )
        elif event.kind == "child_process":
            add(
                "process-spawn",
                "Extension attempted to spawn a process",
                "high",
                "process execution was blocked by the sandbox harness",
                evidence,
                True,
            )
        elif event.kind == "terminal" and event.operation == "sendText":
            add(
                "terminal-command",
                "Extension attempted to send text to an integrated terminal",
                "high",
                "terminal command execution was blocked by the sandbox harness",
                evidence,
                True,
            )
        elif event.kind == "env" and event.canary:
            add(
                "canary-env-read",
                "Extension read canary environment material",
                "high",
                "process.env access reached a Red Widow canary environment value",
                evidence,
                True,
            )
        elif event.kind == "webview" and event.operation == "enableScripts":
            add(
                "webview-enable-scripts",
                "Extension created a script-enabled webview",
                "medium",
                "webview JavaScript execution was enabled during activation or command execution",
                evidence,
                False,
            )
        elif event.kind == "webview" and event.operation == "setHtml" and "missing csp" in event.detail.lower():
            add(
                "webview-missing-csp",
                "Extension assigned scriptable webview HTML without a strict CSP",
                "high",
                "scriptable webview HTML lacked an apparent strict Content-Security-Policy",
                evidence,
                True,
            )
        elif event.kind == "webview" and event.operation == "onDidReceiveMessage":
            add(
                "webview-message-handler",
                "Extension registered a webview message handler",
                "medium",
                "webview message handlers require input validation before touching workspace APIs",
                evidence,
                False,
            )
        elif event.kind in {"fetch", "http", "https", "net", "tls"}:
            add(
                "network-on-activation",
                "Extension attempted outbound network access",
                "medium",
                "network access during activation or command execution was blocked by the harness",
                evidence,
                False,
            )

    for error in errors:
        add(
            "harness-error",
            "Dynamic harness reported an execution error",
            "low",
            "extension execution did not complete cleanly in the sandbox harness",
            error,
            False,
        )

    return violations


def _event_evidence(event: DynamicEvent) -> str:
    parts = [event.kind, event.operation]
    if event.target:
        parts.append(event.target)
    if event.detail:
        parts.append(event.detail)
    if event.blocked:
        parts.append("blocked")
    if event.canary:
        parts.append("canary")
    return " | ".join(parts)
