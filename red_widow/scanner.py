from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable
from urllib.parse import urlparse

from .models import DiffReport, Finding, ScanReport


MAX_TEXT_BYTES = 1_500_000
MAX_EVIDENCE_PER_RULE = 3
MAX_PACKAGE_FILES = 100_000
MAX_TOTAL_SAMPLE_BYTES = 128 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024

TEXT_EXTENSIONS = {
    "",
    ".cjs",
    ".css",
    ".env",
    ".html",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".md",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

SOURCE_EXTENSIONS = {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}

NATIVE_EXTENSIONS = {
    ".bin",
    ".dylib",
    ".dll",
    ".exe",
    ".node",
    ".pyd",
    ".so",
}

SENSITIVE_FILE_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "private.key",
}

SENSITIVE_PATH_PATTERNS = {
    ".ssh": "SSH configuration or keys",
    ".git-credentials": "Git credential store",
    ".env": "environment files",
    "id_rsa": "SSH private key filename",
    "id_ed25519": "SSH private key filename",
    "GITHUB_TOKEN": "GitHub token environment variable",
    "AWS_SECRET_ACCESS_KEY": "AWS secret environment variable",
    "GOOGLE_APPLICATION_CREDENTIALS": "Google Cloud credential path",
    "AZURE_CLIENT_SECRET": "Azure client secret environment variable",
}

SECRET_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "private-key",
        "Private key material",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
    ),
    (
        "aws-access-key",
        "AWS access key",
        "high",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "github-token",
        "GitHub token",
        "critical",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"),
    ),
    (
        "openai-key",
        "OpenAI API key",
        "critical",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "slack-token",
        "Slack token",
        "high",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "npm-token",
        "npm token",
        "high",
        re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    ),
    (
        "generic-secret",
        "Generic secret assignment",
        "medium",
        re.compile(
            r"(?i)\b(?:api[_-]?key|token|secret|password|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{24,})"
        ),
    ),
)

URL_RE = re.compile(r"https?://[^\s'\"`<>()\[\]{}]+", re.IGNORECASE)
CHILD_PROCESS_RE = re.compile(
    r"(?:require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    r"from\s+['\"](?:node:)?child_process['\"]|"
    r"import\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)|"
    r"\b(?:exec|execFile|fork|spawn|execSync|spawnSync)\s*\()"
)
OBFUSCATION_RE = re.compile(r"\b(?:eval|atob)\s*\(|new\s+Function\s*\(|String\.fromCharCode\s*\(")
BASE64_BLOB_RE = re.compile(r"['\"][A-Za-z0-9+/]{220,}={0,2}['\"]")
WEBVIEW_ENABLE_SCRIPTS_RE = re.compile(r"\benableScripts\s*:\s*true\b")
WEBVIEW_CREATE_RE = re.compile(r"\bcreateWebviewPanel\s*\(")
WEBVIEW_HTML_ASSIGN_RE = re.compile(r"\.webview\s*\.\s*html\s*=")
WEBVIEW_MESSAGE_HANDLER_RE = re.compile(
    r"(?:\.webview\s*\.\s*)?onDidReceiveMessage\s*\("
)
WEBVIEW_SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
TERMINAL_CREATE_RE = re.compile(r"\bcreateTerminal\s*\(")
TERMINAL_SEND_TEXT_RE = re.compile(r"\.sendText\s*\(")
TERMINAL_VARIABLE_SEND_TEXT_RE = re.compile(r"\b(?:terminal|term)\s*\.\s*sendText\s*\(")
ENV_ENUMERATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bObject\.(?:keys|values|entries)\s*\(\s*process\.env\s*\)"),
    re.compile(r"\bJSON\.stringify\s*\(\s*process\.env\s*(?:[,)]|\})"),
    re.compile(r"\bfor\s*\([^)]*\bin\s+process\.env\s*\)"),
    re.compile(r"\.\.\.\s*process\.env\b"),
    re.compile(r"\bprocess\.env\s*\[[^\]]+\]"),
    re.compile(r"=\s*process\.env\b(?!\s*\.)"),
)
SECRET_STORAGE_RE = re.compile(
    r"\bcontext\.secrets\b|\b[A-Za-z_$][\w$]*\.secrets\.(?:get|store|delete)\s*\("
)
NETWORK_RUNTIME_RE = re.compile(
    r"\b(?:fetch|axios\.(?:get|post|put|request)|https?\.(?:get|request)|"
    r"net\.(?:connect|createConnection)|tls\.(?:connect|createConnection))\s*\("
)
FS_WRITE_RE = re.compile(
    r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|"
    r"copyFile|copyFileSync|chmod|chmodSync)\s*\("
)
FILE_READ_RE = re.compile(
    r"\b(?:readFile|readFileSync|createReadStream|openTextDocument)\s*\(|"
    r"\bworkspace\.fs\.readFile\s*\("
)
PROCESS_ENV_ACCESS_RE = re.compile(r"\bprocess\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|\s*\[)")
WORKSPACE_TRUST_RE = re.compile(
    r"\b(?:vscode\.)?workspace\.isTrusted\b|\bonDidGrantWorkspaceTrust\s*\("
)
LANGUAGE_MODEL_TOOL_BROAD_RE = re.compile(
    r"\b(?:shell|terminal|command|execute|run|filesystem|file|workspace|secret|credential|network|http|fetch)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PackageFile:
    path: str
    size: int
    sample: bytes
    role: str = "unknown"

    @property
    def suffix(self) -> str:
        return Path(self.path).suffix.lower()

    @property
    def name(self) -> str:
        return Path(self.path).name

    def text(self) -> str | None:
        if self.suffix not in TEXT_EXTENSIONS and self.name not in SENSITIVE_FILE_NAMES:
            return None
        if b"\x00" in self.sample[:4096]:
            return None
        try:
            return self.sample.decode("utf-8")
        except UnicodeDecodeError:
            return self.sample.decode("utf-8", errors="ignore")


def scan_target(target: str | Path) -> ScanReport:
    path = Path(target).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"target does not exist: {path}")

    files, digest = _read_package(path)
    manifest_path, manifest = _find_manifest(files)
    files = _classify_files(files, manifest_path, manifest)
    report = _build_report(path, files, digest, manifest_path, manifest)
    report.findings = _dedupe_findings(
        _scan_manifest(manifest_path, manifest) + _scan_files(files, manifest_path, manifest)
    )
    report.domains = tuple(sorted(_collect_domains(files)))
    report.native_binaries = tuple(sorted(_collect_native_binaries(files)))
    return report


def diff_targets(old_target: str | Path, new_target: str | Path) -> DiffReport:
    old = scan_target(old_target)
    new = scan_target(new_target)

    old_findings = {finding.key(): finding for finding in old.findings}
    new_findings = {finding.key(): finding for finding in new.findings}
    added_keys = sorted(set(new_findings) - set(old_findings))
    removed_keys = sorted(set(old_findings) - set(new_findings))

    added_domains = tuple(sorted(set(new.domains) - set(old.domains)))
    removed_domains = tuple(sorted(set(old.domains) - set(new.domains)))
    added_native = tuple(sorted(set(new.native_binaries) - set(old.native_binaries)))
    removed_native = tuple(sorted(set(old.native_binaries) - set(new.native_binaries)))

    return DiffReport(
        old=old,
        new=new,
        added_findings=[new_findings[key] for key in added_keys],
        removed_findings=[old_findings[key] for key in removed_keys],
        added_domains=added_domains,
        removed_domains=removed_domains,
        added_native_binaries=added_native,
        removed_native_binaries=removed_native,
        activation_changed=old.activation_events != new.activation_events,
    )


def discover_installed_extensions(extra_roots: Iterable[str | Path] = ()) -> list[Path]:
    home = Path.home()
    roots = [
        home / ".vscode" / "extensions",
        home / ".vscode-insiders" / "extensions",
        home / ".vscode-oss" / "extensions",
        home / ".vscodium" / "extensions",
        home / ".cursor" / "extensions",
        home / ".windsurf" / "extensions",
        home / ".trae" / "extensions",
    ]

    appdata = os.environ.get("APPDATA")
    userprofile = os.environ.get("USERPROFILE")
    if appdata:
        roots.extend(
            [
                Path(appdata) / "Code" / "User" / "extensions",
                Path(appdata) / "Cursor" / "User" / "extensions",
                Path(appdata) / "VSCodium" / "User" / "extensions",
            ]
        )
    if userprofile:
        profile = Path(userprofile)
        roots.extend([profile / ".vscode" / "extensions", profile / ".cursor" / "extensions"])

    roots.extend(Path(root).expanduser() for root in extra_roots)

    extension_dirs: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        with suppress(OSError):
            for child in root.iterdir():
                if not child.is_dir() or not (child / "package.json").is_file():
                    continue
                resolved = child.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                extension_dirs.append(child)
    return sorted(extension_dirs)


def make_lockfile(reports: Iterable[ScanReport]) -> dict[str, Any]:
    allowed: dict[str, dict[str, str]] = {}
    for report in reports:
        allowed[report.extension_id] = {
            "version": report.version,
            "sha256": report.package_sha256,
            "source": "local",
            "approvedBy": "",
        }
    return {"allowedExtensions": allowed}


def validate_lockfile(reports: Iterable[ScanReport], lockfile: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    allowed = lockfile.get("allowedExtensions")
    if not isinstance(allowed, dict):
        return ["lockfile is missing an object at allowedExtensions"]

    for report in reports:
        entry = allowed.get(report.extension_id)
        if not isinstance(entry, dict):
            errors.append(f"{report.extension_id}: extension is not present in lockfile")
            continue
        expected_version = entry.get("version")
        expected_sha = entry.get("sha256")
        if expected_version and expected_version != report.version:
            errors.append(
                f"{report.extension_id}: version {report.version or '<unknown>'} "
                f"does not match lockfile version {expected_version}"
            )
        if expected_sha and expected_sha != report.package_sha256:
            errors.append(f"{report.extension_id}: package digest does not match lockfile")
    return errors


def _read_package(path: Path) -> tuple[list[PackageFile], str]:
    if path.is_dir():
        return _read_directory(path)
    if zipfile.is_zipfile(path):
        return _read_zip(path)
    raise ValueError(f"target is neither a directory nor a VSIX/ZIP package: {path}")


def _read_directory(path: Path) -> tuple[list[PackageFile], str]:
    digest = hashlib.sha256()
    files: list[PackageFile] = []
    sample_budget = MAX_TOTAL_SAMPLE_BYTES
    root = path.resolve(strict=True)

    for file_path in sorted(path.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue
        resolved = file_path.resolve(strict=True)
        if not _is_relative_to(resolved, root):
            continue
        if len(files) >= MAX_PACKAGE_FILES:
            raise ValueError(f"package contains more than {MAX_PACKAGE_FILES} files")
        rel_path = file_path.relative_to(path).as_posix()
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\0")
        sample = bytearray()
        sample_limit = min(MAX_TEXT_BYTES, sample_budget)
        with file_path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                remaining = sample_limit - len(sample)
                if remaining > 0:
                    sample.extend(chunk[:remaining])
        sample_budget -= len(sample)
        size = file_path.stat().st_size
        files.append(PackageFile(path=rel_path, size=size, sample=bytes(sample)))

    return files, digest.hexdigest()


def _read_zip(path: Path) -> tuple[list[PackageFile], str]:
    package_digest = _file_sha256(path)
    files: list[PackageFile] = []
    sample_budget = MAX_TOTAL_SAMPLE_BYTES
    total_uncompressed = 0
    seen_paths: set[str] = set()

    with zipfile.ZipFile(path) as archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        if len(entries) > MAX_PACKAGE_FILES:
            raise ValueError(f"package contains more than {MAX_PACKAGE_FILES} files")
        for info in sorted(entries, key=lambda i: i.filename):
            member_path = normalize_archive_member_path(info.filename)
            if member_path in seen_paths:
                raise ValueError(f"duplicate path in VSIX archive: {member_path}")
            seen_paths.add(member_path)
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ValueError(
                    "VSIX archive declares more than "
                    f"{MAX_ZIP_UNCOMPRESSED_BYTES} uncompressed bytes"
                )
            sample_limit = max(0, min(MAX_TEXT_BYTES, sample_budget))
            try:
                with archive.open(info, "r") as fh:
                    sample = fh.read(sample_limit) if sample_limit else b""
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                raise ValueError(f"could not read VSIX archive member {member_path}: {exc}") from exc
            sample_budget -= len(sample)
            files.append(
                PackageFile(path=member_path, size=info.file_size, sample=sample)
            )

    return files, package_digest


def _find_manifest(files: list[PackageFile]) -> tuple[str, dict[str, Any]]:
    candidates = [file for file in files if file.path.endswith("package.json")]
    candidates.sort(key=lambda file: (file.path != "extension/package.json", file.path.count("/"), file.path))
    for candidate in candidates:
        text = candidate.text()
        if not text:
            continue
        with suppress(json.JSONDecodeError):
            manifest = json.loads(text)
            if is_extension_manifest(manifest):
                return candidate.path, manifest
    raise ValueError("could not find a VS Code extension package.json manifest")


def _build_report(
    target: Path,
    files: list[PackageFile],
    digest: str,
    manifest_path: str,
    manifest: dict[str, Any],
) -> ScanReport:
    publisher = _as_str(manifest.get("publisher"))
    name = _as_str(manifest.get("name"))
    extension_id = f"{publisher}.{name}" if publisher and name else name or "unknown"
    activation_events = manifest.get("activationEvents")
    if not isinstance(activation_events, list):
        activation_events = []

    return ScanReport(
        target=str(target),
        package_sha256=digest,
        extension_id=extension_id,
        publisher=publisher,
        name=name,
        display_name=_as_str(manifest.get("displayName")),
        version=_as_str(manifest.get("version")),
        editor=_infer_editor(target),
        install_source=_infer_install_source(target),
        manifest_path=manifest_path,
        activation_events=tuple(str(event) for event in activation_events),
        file_count=len(files),
        total_size=sum(file.size for file in files),
    )


def _scan_manifest(manifest_path: str, manifest: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    activation_events = manifest.get("activationEvents")
    if isinstance(activation_events, list) and "*" in activation_events:
        findings.append(
            Finding(
                rule_id="activation-star",
                title="Extension activates for every workspace",
                severity="medium",
                path=manifest_path,
                detail="activationEvents contains '*'",
                scope="manifest",
            )
        )

    scripts = manifest.get("scripts")
    if isinstance(scripts, dict):
        risky_scripts = sorted(
            key for key in scripts if key in {"preinstall", "install", "postinstall", "prepare"}
        )
        if risky_scripts:
            findings.append(
                Finding(
                    rule_id="package-lifecycle-script",
                    title="Package lifecycle script",
                    severity="medium",
                    path=manifest_path,
                    detail=", ".join(risky_scripts),
                    scope="manifest",
                )
            )

    extension_kind = manifest.get("extensionKind")
    if extension_kind == "workspace" or (
        isinstance(extension_kind, list) and "workspace" in extension_kind
    ):
        findings.append(
            Finding(
                rule_id="workspace-extension-kind",
                title="Workspace extension host",
                severity="low",
                path=manifest_path,
                detail="extensionKind includes workspace",
                scope="manifest",
            )
        )
    findings.extend(_scan_language_model_tool_manifest(manifest_path, manifest))
    return findings


def _scan_language_model_tool_manifest(manifest_path: str, manifest: dict[str, Any]) -> list[Finding]:
    tool_names = _language_model_tool_names(manifest)
    if not tool_names:
        return []

    findings = [
        Finding(
            rule_id="language-model-tool-contributed",
            title="Extension contributes language model tools",
            severity="medium",
            path=manifest_path,
            detail=", ".join(tool_names[:8]),
            evidence=tuple(tool_names[:MAX_EVIDENCE_PER_RULE]),
            confidence="high",
            blocking=False,
            scope="manifest",
        )
    ]

    broad_tools = _broad_language_model_tools(manifest)
    if broad_tools:
        findings.append(
            Finding(
                rule_id="language-model-tool-broad-description",
                title="Language model tool description implies broad access",
                severity="medium",
                path=manifest_path,
                detail=", ".join(broad_tools[:8]),
                evidence=tuple(broad_tools[:MAX_EVIDENCE_PER_RULE]),
                confidence="medium",
                blocking=False,
                scope="manifest",
            )
        )
    return findings


def _scan_files(files: list[PackageFile], manifest_path: str, manifest: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    text_files: list[tuple[PackageFile, str]] = []
    for file in files:
        findings.extend(_scan_path(file))
        findings.extend(_scan_binary(file))
        text = file.text()
        if text is None:
            continue
        text_files.append((file, text))
        findings.extend(_scan_text(file, text))
    findings.extend(_scan_language_model_tool_implementation(text_files, manifest))
    findings.extend(_scan_workspace_trust(text_files, manifest_path, manifest))
    return findings


def _scan_path(file: PackageFile) -> list[Finding]:
    lower_parts = [part.lower() for part in Path(file.path).parts]
    name = file.name.lower()
    if name in SENSITIVE_FILE_NAMES or any(part in SENSITIVE_FILE_NAMES for part in lower_parts):
        severity = "medium" if file.role in {"example", "test", "documentation"} else "high"
        return [
            Finding(
                rule_id="sensitive-file-bundled",
                title="Sensitive file bundled in extension",
                severity=severity,
                path=file.path,
                detail=f"{file.name} should not usually be distributed in a VSIX",
                scope=file.role,
            )
        ]
    return []


def _scan_binary(file: PackageFile) -> list[Finding]:
    findings: list[Finding] = []
    if file.suffix in NATIVE_EXTENSIONS or _has_binary_magic(file.sample):
        dependency_like = file.role in {"dependency", "generated", "test", "example"}
        findings.append(
            Finding(
                rule_id="native-binary",
                title="Native binary bundled in extension",
                severity="medium" if dependency_like else "high",
                path=file.path,
                detail=f"{file.size} bytes",
                confidence="medium" if dependency_like else "high",
                blocking=False,
                scope=file.role,
            )
        )
    elif file.suffix in {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}:
        low_signal = file.role in {"dependency", "test", "example", "documentation"}
        findings.append(
            Finding(
                rule_id="shell-script",
                title="Shell script bundled in extension",
                severity="low" if low_signal else "medium",
                path=file.path,
                detail=f"{file.size} bytes",
                confidence="low" if low_signal else "medium",
                blocking=False,
                scope=file.role,
            )
        )
    return findings


def _scan_text(file: PackageFile, text: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_secrets(file, text))
    if file.role != "documentation":
        findings.extend(_scan_child_process(file, text))
        findings.extend(_scan_sensitive_paths(file, text))
        findings.extend(_scan_webview(file, text))
        findings.extend(_scan_terminal(file, text))
        findings.extend(_scan_env_var_enumeration(file, text))
        findings.extend(_scan_secret_storage(file, text))
        findings.extend(_scan_executable_download_chain(file, text))
        findings.extend(_scan_obfuscation(file, text))
    domains = _domains_from_text(text) if _is_runtime_domain_scope(file) else set()
    if domains:
        findings.append(
            Finding(
                rule_id="network-endpoints",
                title="Network endpoints embedded in extension",
                severity="low",
                path=file.path,
                detail=", ".join(sorted(domains)[:8]),
                confidence="high" if file.role in {"source", "manifest", "config"} else "low",
                blocking=False,
                scope=file.role,
            )
        )
    return findings


def _scan_secrets(file: PackageFile, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, title, severity, pattern in SECRET_PATTERNS:
        if rule_id == "generic-secret" and file.role not in {"source", "manifest", "config"}:
            continue
        evidence: list[str] = []
        for match in pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            value = match.group(1) if match.lastindex else match.group(0)
            evidence.append(f"line {line_no}: {_redact(value)}")
            if len(evidence) >= MAX_EVIDENCE_PER_RULE:
                break
        if evidence:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    path=file.path,
                    detail=f"{len(evidence)} sample match(es)",
                    evidence=tuple(evidence),
                    confidence="high" if rule_id != "generic-secret" else "medium",
                    blocking=rule_id != "generic-secret",
                    scope=file.role,
                )
            )
    return findings


def _scan_child_process(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return []
    if file.role in {"test", "example"}:
        severity = "low"
        confidence = "low"
        blocking = False
    elif file.role in {"dependency", "generated"}:
        severity = "medium"
        confidence = "low"
        blocking = False
    else:
        severity = "high"
        confidence = "high"
        blocking = True
    evidence: list[str] = []
    for match in CHILD_PROCESS_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        evidence.append(f"line {line_no}: {match.group(0)[:80]}")
        if len(evidence) >= MAX_EVIDENCE_PER_RULE:
            break
    if not evidence:
        return []
    return [
        Finding(
            rule_id="child-process-use",
            title="Node process execution API",
            severity=severity,
            path=file.path,
            detail="extension code references child_process or process spawning APIs",
            evidence=tuple(evidence),
            confidence=confidence,
            blocking=blocking,
            scope=file.role,
        )
    ]


def _scan_sensitive_paths(file: PackageFile, text: str) -> list[Finding]:
    if file.role in {"dependency", "documentation"}:
        return []
    severity = "low" if file.role in {"test", "example"} else "medium"
    confidence = "low" if file.role in {"test", "example"} else "medium"
    evidence: list[str] = []
    for needle, reason in SENSITIVE_PATH_PATTERNS.items():
        index = text.find(needle)
        if index == -1:
            continue
        line_no = text.count("\n", 0, index) + 1
        evidence.append(f"line {line_no}: {reason}")
        if len(evidence) >= MAX_EVIDENCE_PER_RULE:
            break
    if not evidence:
        return []
    return [
        Finding(
            rule_id="sensitive-path-access",
            title="Sensitive local path reference",
            severity=severity,
            path=file.path,
            detail="code references local secret or credential paths",
            evidence=tuple(evidence),
            confidence=confidence,
            blocking=False,
            scope=file.role,
        )
    ]


def _scan_webview(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in SOURCE_EXTENSIONS:
        return []

    findings: list[Finding] = []
    low_signal = file.role in {"dependency", "generated", "test", "example"}
    severity = "low" if low_signal else "medium"
    confidence = "low" if low_signal else "medium"

    enable_evidence = _evidence_for_pattern(text, WEBVIEW_ENABLE_SCRIPTS_RE)
    if enable_evidence:
        findings.append(
            Finding(
                rule_id="webview-enable-scripts",
                title="Webview enables JavaScript",
                severity=severity,
                path=file.path,
                detail="enableScripts is set to true",
                evidence=tuple(enable_evidence),
                confidence=confidence,
                blocking=False,
                scope=file.role,
            )
        )

    handler_evidence = _evidence_for_pattern(text, WEBVIEW_MESSAGE_HANDLER_RE)
    if handler_evidence:
        findings.append(
            Finding(
                rule_id="webview-message-handler",
                title="Webview receives messages from web content",
                severity=severity,
                path=file.path,
                detail="onDidReceiveMessage handler registered",
                evidence=tuple(handler_evidence),
                confidence=confidence,
                blocking=False,
                scope=file.role,
            )
        )

    if _has_webview_script_surface(text) and not _has_strict_webview_csp(text):
        evidence = _evidence_for_pattern(text, WEBVIEW_HTML_ASSIGN_RE)
        if not evidence:
            evidence = _evidence_for_pattern(text, WEBVIEW_CREATE_RE)
        findings.append(
            Finding(
                rule_id="webview-missing-csp",
                title="Scriptable webview lacks a strict CSP",
                severity="medium" if low_signal else "high",
                path=file.path,
                detail="webview HTML or scripts appear without a strict Content-Security-Policy",
                evidence=tuple(evidence),
                confidence="low" if low_signal else "high",
                blocking=not low_signal and file.role == "source",
                scope=file.role,
            )
        )

    return findings


def _scan_terminal(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in SOURCE_EXTENSIONS or not _has_terminal_send_text(text):
        return []

    low_signal = file.role in {"dependency", "generated", "test", "example"}
    return [
        Finding(
            rule_id="terminal-send-text",
            title="Extension sends commands to an integrated terminal",
            severity="medium" if low_signal else "high",
            path=file.path,
            detail="createTerminal/sendText can inject shell commands into a workspace terminal",
            evidence=tuple(_evidence_for_pattern(text, TERMINAL_SEND_TEXT_RE)),
            confidence="low" if low_signal else "high",
            blocking=not low_signal and file.role == "source",
            scope=file.role,
        )
    ]


def _scan_env_var_enumeration(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in SOURCE_EXTENSIONS:
        return []

    evidence: list[str] = []
    for pattern in ENV_ENUMERATION_PATTERNS:
        evidence.extend(_evidence_for_pattern(text, pattern, limit=MAX_EVIDENCE_PER_RULE - len(evidence)))
        if len(evidence) >= MAX_EVIDENCE_PER_RULE:
            break
    if not evidence:
        return []

    low_signal = file.role in {"dependency", "generated", "test", "example"}
    return [
        Finding(
            rule_id="env-var-enumeration",
            title="Extension broadly reads environment variables",
            severity="low" if low_signal else "medium",
            path=file.path,
            detail="process.env is enumerated or dynamically indexed",
            evidence=tuple(evidence),
            confidence="low" if low_signal else "medium",
            blocking=False,
            scope=file.role,
        )
    ]


def _scan_secret_storage(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in SOURCE_EXTENSIONS:
        return []

    evidence = _evidence_for_pattern(text, SECRET_STORAGE_RE)
    if not evidence:
        return []

    low_signal = file.role in {"dependency", "generated", "test", "example"}
    return [
        Finding(
            rule_id="secret-storage-access",
            title="Extension accesses VS Code secret storage",
            severity="low" if low_signal else "medium",
            path=file.path,
            detail="context.secrets or ExtensionContext secret storage APIs are referenced",
            evidence=tuple(evidence),
            confidence="low" if low_signal else "medium",
            blocking=False,
            scope=file.role,
        )
    ]


def _scan_executable_download_chain(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in SOURCE_EXTENSIONS or file.role != "source":
        return []
    if not _has_executable_download_chain(text):
        return []

    evidence = [
        _first_evidence(text, NETWORK_RUNTIME_RE, "network"),
        _first_evidence(text, FS_WRITE_RE, "write"),
        _first_evidence(text, CHILD_PROCESS_RE, "execute"),
    ]
    return [
        Finding(
            rule_id="executable-download-chain",
            title="Runtime download-write-execute chain",
            severity="high",
            path=file.path,
            detail="network download, filesystem write, and process execution appear in the same runtime source file",
            evidence=tuple(item for item in evidence if item),
            confidence="high",
            blocking=True,
            scope=file.role,
        )
    ]


def _scan_language_model_tool_implementation(
    text_files: list[tuple[PackageFile, str]],
    manifest: dict[str, Any],
) -> list[Finding]:
    if not _language_model_tool_names(manifest):
        return []

    for file, text in text_files:
        if file.role != "source" or file.suffix not in SOURCE_EXTENSIONS:
            continue
        input_evidence = _language_model_tool_input_evidence(text)
        output_evidence = _language_model_tool_output_evidence(text)
        if input_evidence and output_evidence:
            return [
                Finding(
                    rule_id="language-model-tool-exfil-path",
                    title="Language model tool code can move local data to an output path",
                    severity="high",
                    path=file.path,
                    detail="source combines local file/env/secret access with network, process, or terminal output",
                    evidence=(input_evidence, output_evidence),
                    confidence="high",
                    blocking=True,
                    scope=file.role,
                )
            ]
    return []


def _scan_workspace_trust(
    text_files: list[tuple[PackageFile, str]],
    manifest_path: str,
    manifest: dict[str, Any],
) -> list[Finding]:
    source_texts = [text for file, text in text_files if file.role == "source" and file.suffix in SOURCE_EXTENSIONS]
    if not source_texts or any(WORKSPACE_TRUST_RE.search(text) for text in source_texts):
        return []
    if _untrusted_workspace_supported_false(manifest):
        return []

    findings: list[Finding] = []
    risky_sources = [
        (file, text, _workspace_trust_evidence(text))
        for file, text in text_files
        if file.role == "source" and file.suffix in SOURCE_EXTENSIONS
    ]
    risky_sources = [(file, text, evidence) for file, text, evidence in risky_sources if evidence]
    if not risky_sources:
        return []

    risky_config_ids = _risky_unrestricted_configuration_ids(manifest)
    if risky_config_ids:
        findings.append(
            Finding(
                rule_id="workspace-trust-risky-unrestricted-config",
                title="Execution-sensitive settings are not restricted in untrusted workspaces",
                severity="medium",
                path=manifest_path,
                detail=", ".join(risky_config_ids[:8]),
                evidence=tuple(risky_config_ids[:MAX_EVIDENCE_PER_RULE]),
                confidence="medium",
                blocking=False,
                scope="manifest",
            )
        )
    if not _has_untrusted_workspace_capability(manifest):
        findings.append(
            Finding(
                rule_id="workspace-trust-missing-capability",
                title="Extension lacks explicit Workspace Trust capability metadata",
                severity="medium",
                path=manifest_path,
                detail="risky runtime behavior exists but capabilities.untrustedWorkspaces is not declared",
                confidence="medium",
                blocking=False,
                scope="manifest",
            )
        )
    for file, _, evidence in risky_sources:
        findings.append(
            Finding(
                rule_id="workspace-trust-unchecked",
                title="Risky runtime behavior lacks workspace trust gating",
                severity="medium",
                path=file.path,
                detail="source uses risky runtime APIs without an apparent vscode.workspace.isTrusted check",
                evidence=(evidence,),
                confidence="medium",
                blocking=False,
                scope=file.role,
            )
        )
    return findings


def _scan_obfuscation(file: PackageFile, text: str) -> list[Finding]:
    if file.suffix not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return []

    findings: list[Finding] = []
    low_signal = file.role in {"dependency", "generated", "test", "example"}
    longest_line = max((len(line) for line in text.splitlines()), default=0)
    if longest_line > 2500:
        findings.append(
            Finding(
                rule_id="minified-javascript",
                title="Large minified JavaScript line",
                severity="low" if low_signal else "medium",
                path=file.path,
                detail=f"longest line is {longest_line} characters",
                confidence="low",
                blocking=False,
                scope=file.role,
            )
        )

    evidence: list[str] = []
    for match in OBFUSCATION_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        evidence.append(f"line {line_no}: {match.group(0)}")
        if len(evidence) >= MAX_EVIDENCE_PER_RULE:
            break
    if evidence:
        findings.append(
            Finding(
                rule_id="obfuscation-api",
                title="Obfuscation-related JavaScript API",
                severity="low" if low_signal else "medium",
                path=file.path,
                detail="eval, atob, Function constructor, or String.fromCharCode",
                evidence=tuple(evidence),
                confidence="low" if low_signal else "medium",
                blocking=False,
                scope=file.role,
            )
        )

    if BASE64_BLOB_RE.search(text):
        findings.append(
            Finding(
                rule_id="large-base64-blob",
                title="Large encoded string",
                severity="low" if low_signal else "medium",
                path=file.path,
                detail="large base64-like string literal",
                confidence="low",
                blocking=False,
                scope=file.role,
            )
        )

    return findings


def _has_webview_script_surface(text: str) -> bool:
    if not (WEBVIEW_CREATE_RE.search(text) or WEBVIEW_HTML_ASSIGN_RE.search(text)):
        return False
    return bool(WEBVIEW_ENABLE_SCRIPTS_RE.search(text) or WEBVIEW_SCRIPT_RE.search(text))


def _has_strict_webview_csp(text: str) -> bool:
    normalized = text.replace("\\'", "'").replace('\\"', '"').lower()
    if "content-security-policy" not in normalized:
        return False
    if "default-src 'none'" not in normalized and 'default-src "none"' not in normalized:
        return False
    return "script-src" in normalized


def _has_terminal_send_text(text: str) -> bool:
    if not TERMINAL_SEND_TEXT_RE.search(text):
        return False
    return bool(TERMINAL_CREATE_RE.search(text) or TERMINAL_VARIABLE_SEND_TEXT_RE.search(text))


def _has_executable_download_chain(text: str) -> bool:
    return bool(
        NETWORK_RUNTIME_RE.search(text)
        and FS_WRITE_RE.search(text)
        and CHILD_PROCESS_RE.search(text)
    )


def _workspace_trust_evidence(text: str) -> str:
    if _has_executable_download_chain(text):
        return _first_evidence(text, NETWORK_RUNTIME_RE, "download-write-execute")
    if _has_terminal_send_text(text):
        return _first_evidence(text, TERMINAL_SEND_TEXT_RE, "terminal")
    if CHILD_PROCESS_RE.search(text):
        return _first_evidence(text, CHILD_PROCESS_RE, "process")
    return ""


def _language_model_tool_names(manifest: dict[str, Any]) -> list[str]:
    tools = _language_model_tools(manifest)
    names: list[str] = []
    for index, tool in enumerate(tools, start=1):
        name = _as_str(tool.get("name") or tool.get("displayName")) if isinstance(tool, dict) else ""
        names.append(name or f"tool-{index}")
    return names


def _language_model_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    contributes = manifest.get("contributes")
    if not isinstance(contributes, dict):
        return []
    tools = contributes.get("languageModelTools")
    if not isinstance(tools, list):
        return []
    return [tool for tool in tools if isinstance(tool, dict)]


def _broad_language_model_tools(manifest: dict[str, Any]) -> list[str]:
    broad: list[str] = []
    for tool in _language_model_tools(manifest):
        name = _as_str(tool.get("name") or tool.get("displayName")) or "<unnamed>"
        description = _as_str(tool.get("description"))
        if description and LANGUAGE_MODEL_TOOL_BROAD_RE.search(description):
            broad.append(f"{name}: {description[:120]}")
    return broad


def _language_model_tool_input_evidence(text: str) -> str:
    for pattern, label in (
        (FILE_READ_RE, "file-read"),
        (PROCESS_ENV_ACCESS_RE, "env-read"),
        (SECRET_STORAGE_RE, "secret-storage"),
    ):
        evidence = _first_evidence(text, pattern, label)
        if evidence:
            return evidence
    for pattern in ENV_ENUMERATION_PATTERNS:
        evidence = _first_evidence(text, pattern, "env-read")
        if evidence:
            return evidence
    return ""


def _language_model_tool_output_evidence(text: str) -> str:
    for pattern, label in (
        (NETWORK_RUNTIME_RE, "network"),
        (CHILD_PROCESS_RE, "process"),
        (TERMINAL_SEND_TEXT_RE, "terminal"),
    ):
        evidence = _first_evidence(text, pattern, label)
        if evidence:
            return evidence
    return ""


def _has_untrusted_workspace_capability(manifest: dict[str, Any]) -> bool:
    return isinstance(_untrusted_workspace_config(manifest), dict)


def _untrusted_workspace_supported_false(manifest: dict[str, Any]) -> bool:
    config = _untrusted_workspace_config(manifest)
    return isinstance(config, dict) and config.get("supported") is False


def _untrusted_workspace_config(manifest: dict[str, Any]) -> dict[str, Any] | None:
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        return None
    untrusted = capabilities.get("untrustedWorkspaces")
    return untrusted if isinstance(untrusted, dict) else None


def _restricted_configuration_ids(manifest: dict[str, Any]) -> set[str]:
    config = _untrusted_workspace_config(manifest)
    if not isinstance(config, dict):
        return set()
    restricted = config.get("restrictedConfigurations")
    if not isinstance(restricted, list):
        return set()
    return {str(item) for item in restricted if isinstance(item, str)}


def _risky_unrestricted_configuration_ids(manifest: dict[str, Any]) -> list[str]:
    sensitive = set(_execution_sensitive_configuration_ids(manifest))
    if not sensitive:
        return []
    restricted = _restricted_configuration_ids(manifest)
    return sorted(sensitive - restricted)


def _execution_sensitive_configuration_ids(manifest: dict[str, Any]) -> list[str]:
    contributes = manifest.get("contributes")
    if not isinstance(contributes, dict):
        return []
    configuration = contributes.get("configuration")
    configs = configuration if isinstance(configuration, list) else [configuration]
    setting_ids: list[str] = []
    for config in configs:
        if not isinstance(config, dict):
            continue
        properties = config.get("properties")
        if not isinstance(properties, dict):
            continue
        for key in properties:
            if _configuration_id_affects_execution(str(key)):
                setting_ids.append(str(key))
    return setting_ids


def _configuration_id_affects_execution(setting_id: str) -> bool:
    lowered = setting_id.lower()
    return any(token in lowered for token in ("command", "executable", "runtime", "path", "args", "envfile", "shell"))


def _evidence_for_pattern(
    text: str,
    pattern: re.Pattern[str],
    limit: int = MAX_EVIDENCE_PER_RULE,
) -> list[str]:
    evidence: list[str] = []
    if limit <= 0:
        return evidence
    for match in pattern.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        evidence.append(f"line {line_no}: {match.group(0)[:80]}")
        if len(evidence) >= limit:
            break
    return evidence


def _first_evidence(text: str, pattern: re.Pattern[str], label: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    line_no = text.count("\n", 0, match.start()) + 1
    return f"line {line_no}: {label}: {match.group(0)[:80]}"


def _collect_domains(files: list[PackageFile]) -> set[str]:
    domains: set[str] = set()
    for file in files:
        if not _is_runtime_domain_scope(file):
            continue
        text = file.text()
        if text:
            domains.update(_domains_from_text(text))
    return domains


def _collect_native_binaries(files: list[PackageFile]) -> set[str]:
    return {
        file.path
        for file in files
        if file.suffix in NATIVE_EXTENSIONS or _has_binary_magic(file.sample)
    }


def _classify_files(
    files: list[PackageFile], manifest_path: str, manifest: dict[str, Any]
) -> list[PackageFile]:
    entry_paths = _runtime_entry_paths(manifest)
    classified: list[PackageFile] = []
    for file in files:
        role = _classify_file(file.path, manifest_path, entry_paths)
        classified.append(PackageFile(path=file.path, size=file.size, sample=file.sample, role=role))
    return classified


def _runtime_entry_paths(manifest: dict[str, Any]) -> set[str]:
    entries: set[str] = set()
    for key in ("main", "browser"):
        value = manifest.get(key)
        if isinstance(value, str) and value:
            normalized = value.strip("./")
            entries.add(normalized)
            entries.add(f"extension/{normalized}")
            parent = str(Path(normalized).parent).strip(".")
            if parent:
                entries.add(parent.rstrip("/") + "/")
                entries.add(f"extension/{parent.rstrip('/')}/")
    return entries


def _classify_file(path: str, manifest_path: str, entry_paths: set[str]) -> str:
    normalized = path.strip("./")
    lower = normalized.lower()
    parts = [part.lower() for part in Path(lower).parts]
    name = Path(lower).name
    suffix = Path(lower).suffix

    if normalized == manifest_path:
        return "manifest"
    if "node_modules" in parts:
        return "dependency"
    if any(part in {"test", "tests", "__tests__", "spec", "fixtures"} for part in parts):
        return "test"
    if any(part in {"example", "examples", "sample", "samples"} for part in parts):
        return "example"
    if name in {"readme.md", "changelog.md", "license", "license.md", "notice", "notice.md"}:
        return "documentation"
    if parts and (parts[0] in {"docs", "doc"} or (len(parts) > 1 and parts[1] in {"docs", "doc"})):
        return "documentation"
    if suffix in {".md", ".markdown", ".rst"}:
        return "documentation"
    if name.endswith(".min.js") or suffix == ".map":
        return "generated"
    if normalized in entry_paths or any(normalized.startswith(entry) for entry in entry_paths if entry.endswith("/")):
        return "source"
    if suffix in SOURCE_EXTENSIONS:
        return "source"
    if name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "tsconfig.json"}:
        return "config"
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return "config"
    return "asset"


def _is_runtime_domain_scope(file: PackageFile) -> bool:
    return file.role == "source"


def _infer_editor(target: Path) -> str:
    value = target.expanduser().as_posix().lower()
    if "/.vscode-insiders/extensions/" in value:
        return "VS Code Insiders"
    if "/.vscode/extensions/" in value:
        return "VS Code"
    if "/.vscode-oss/extensions/" in value or "/.vscodium/extensions/" in value:
        return "VSCodium"
    if "/.cursor/extensions/" in value:
        return "Cursor"
    if "/.windsurf/extensions/" in value:
        return "Windsurf"
    if "/.trae/extensions/" in value:
        return "Trae"
    return ""


def _infer_install_source(target: Path) -> str:
    if zipfile.is_zipfile(target):
        return "vsix"
    return "installed" if _infer_editor(target) else "directory"


def _domains_from_text(text: str) -> set[str]:
    domains: set[str] = set()
    for match in URL_RE.finditer(text):
        parsed = urlparse(match.group(0))
        host = parsed.hostname
        if not host or _is_local_host(host):
            continue
        domains.add(host.lower())
    return domains


def _is_local_host(host: str) -> bool:
    host = host.lower()
    return host in {"localhost", "0.0.0.0", "127.0.0.1", "::1"} or host.endswith(".local")


def normalize_archive_member_path(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    if PureWindowsPath(filename).drive or PurePosixPath(normalized).is_absolute():
        raise ValueError(f"unsafe path in VSIX archive: {filename}")

    parts: list[str] = []
    for part in PurePosixPath(normalized).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"unsafe path in VSIX archive: {filename}")
        parts.append(part)

    if not parts:
        raise ValueError(f"unsafe path in VSIX archive: {filename}")
    return "/".join(parts)


def is_extension_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False

    engines = manifest.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("vscode"), str):
        return True
    if isinstance(manifest.get("activationEvents"), list):
        return True
    if isinstance(manifest.get("contributes"), dict):
        return True
    return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_binary_magic(sample: bytes) -> bool:
    return sample.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"))


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = finding.key()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return sorted(
        deduped,
        key=lambda finding: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(finding.severity, 5),
            finding.rule_id,
            finding.path,
        ),
    )


def _redact(value: str) -> str:
    cleaned = value.strip().strip("'\"")
    if len(cleaned) <= 12:
        return "<redacted>"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""
