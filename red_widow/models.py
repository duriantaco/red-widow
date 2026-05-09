from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
CONFIDENCE_WEIGHTS = {"low": 0.35, "medium": 0.7, "high": 1.0}
SCHEMA_VERSION = "1.0"

RULE_METADATA: dict[str, dict[str, Any]] = {
    "activation-star": {
        "category": "manifest",
        "confidence": "high",
        "blocking": False,
        "remediation": "Prefer narrower activation events so the extension starts only when needed.",
    },
    "package-lifecycle-script": {
        "category": "manifest",
        "confidence": "high",
        "blocking": True,
        "remediation": "Review install-time scripts and require approval before distribution.",
    },
    "workspace-extension-kind": {
        "category": "manifest",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Confirm the extension needs workspace host access.",
    },
    "sensitive-file-bundled": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Remove local credential files from the extension package.",
    },
    "native-binary": {
        "category": "native-code",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Review the binary source, provenance, and target platform before approval.",
    },
    "shell-script": {
        "category": "process-execution",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Review script behavior and avoid install or activation-time execution.",
    },
    "private-key": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the private key from the package.",
    },
    "aws-access-key": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the AWS credential from the package.",
    },
    "github-token": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the GitHub token from the package.",
    },
    "openai-key": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the API key from the package.",
    },
    "slack-token": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the Slack token from the package.",
    },
    "npm-token": {
        "category": "secrets",
        "confidence": "high",
        "blocking": True,
        "remediation": "Revoke and remove the npm token from the package.",
    },
    "generic-secret": {
        "category": "secrets",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Verify whether the value is a real credential and remove it if live.",
    },
    "child-process-use": {
        "category": "process-execution",
        "confidence": "high",
        "blocking": True,
        "remediation": "Review command execution paths and require explicit approval.",
    },
    "sensitive-path-access": {
        "category": "local-credentials",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Confirm why the extension references credential paths.",
    },
    "minified-javascript": {
        "category": "obfuscation",
        "confidence": "low",
        "blocking": False,
        "remediation": "Prefer published source maps or readable source for review.",
    },
    "obfuscation-api": {
        "category": "obfuscation",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Review dynamic code execution or decoding behavior.",
    },
    "large-base64-blob": {
        "category": "obfuscation",
        "confidence": "low",
        "blocking": False,
        "remediation": "Inspect the decoded payload or require source transparency.",
    },
    "network-endpoints": {
        "category": "network",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Review outbound domains and add approved domains to policy.",
    },
    "webview-enable-scripts": {
        "category": "webview",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Enable scripts only when needed and pair them with a strict CSP and message validation.",
    },
    "webview-missing-csp": {
        "category": "webview",
        "confidence": "high",
        "blocking": True,
        "remediation": "Add a strict Content-Security-Policy with default-src 'none' and nonce-based scripts.",
    },
    "webview-message-handler": {
        "category": "webview",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Validate all webview messages before using them in workspace, filesystem, terminal, or network operations.",
    },
    "terminal-send-text": {
        "category": "terminal",
        "confidence": "high",
        "blocking": True,
        "remediation": "Avoid sending commands into user terminals or require an explicit trusted-workspace and user approval gate.",
    },
    "env-var-enumeration": {
        "category": "environment",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Read only named environment variables needed for the extension instead of sweeping process.env.",
    },
    "secret-storage-access": {
        "category": "secrets",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Confirm secret storage access is user-visible and limited to extension-owned values.",
    },
    "executable-download-chain": {
        "category": "supply-chain",
        "confidence": "high",
        "blocking": True,
        "remediation": "Do not download, write, and execute binaries at runtime without provenance and explicit approval.",
    },
    "workspace-trust-unchecked": {
        "category": "workspace-trust",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Gate risky runtime behavior with vscode.workspace.isTrusted or workspace trust events.",
    },
    "workspace-trust-missing-capability": {
        "category": "workspace-trust",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Declare capabilities.untrustedWorkspaces so users know how the extension behaves in Restricted Mode.",
    },
    "workspace-trust-risky-unrestricted-config": {
        "category": "workspace-trust",
        "confidence": "medium",
        "blocking": False,
        "remediation": "List execution-sensitive settings in restrictedConfigurations or avoid using workspace-defined values for commands.",
    },
    "language-model-tool-contributed": {
        "category": "agent-tooling",
        "confidence": "high",
        "blocking": False,
        "remediation": "Review the tool description, input schema, and implementation before enabling agent mode access.",
    },
    "language-model-tool-broad-description": {
        "category": "agent-tooling",
        "confidence": "medium",
        "blocking": False,
        "remediation": "Narrow tool descriptions and schemas so agent calls are scoped and user-reviewable.",
    },
    "language-model-tool-exfil-path": {
        "category": "agent-tooling",
        "confidence": "high",
        "blocking": True,
        "remediation": "Avoid combining secret/file reads with network, process, or terminal output in language model tools.",
    },
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str = ""
    detail: str = ""
    evidence: tuple[str, ...] = ()
    confidence: str = ""
    blocking: bool | None = None
    category: str = ""
    remediation: str = ""
    scope: str = ""

    def __post_init__(self) -> None:
        metadata = RULE_METADATA.get(self.rule_id, {})
        if not self.confidence:
            object.__setattr__(self, "confidence", str(metadata.get("confidence", "medium")))
        if self.blocking is None:
            object.__setattr__(self, "blocking", bool(metadata.get("blocking", False)))
        if not self.category:
            object.__setattr__(self, "category", str(metadata.get("category", "general")))
        if not self.remediation:
            object.__setattr__(self, "remediation", str(metadata.get("remediation", "")))

    def key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.path, self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "path": self.path,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "blocking": bool(self.blocking),
            "category": self.category,
            "remediation": self.remediation,
            "scope": self.scope,
        }


@dataclass
class ScanReport:
    target: str
    package_sha256: str
    extension_id: str = "unknown"
    publisher: str = ""
    name: str = ""
    display_name: str = ""
    version: str = ""
    editor: str = ""
    install_source: str = ""
    manifest_path: str = ""
    activation_events: tuple[str, ...] = ()
    file_count: int = 0
    total_size: int = 0
    domains: tuple[str, ...] = ()
    native_binaries: tuple[str, ...] = ()
    scan_warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        score = 0
        for finding in self.findings:
            base = SEVERITY_WEIGHTS.get(finding.severity, 0)
            confidence = CONFIDENCE_WEIGHTS.get(finding.confidence, 0.7)
            blocking = 1.0 if finding.blocking else 0.6
            score += round(base * confidence * blocking)
        return score

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score >= 18:
            return "Critical"
        if score >= 10:
            return "High"
        if score >= 5:
            return "Medium"
        return "Low"

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "target": self.target,
            "extensionId": self.extension_id,
            "publisher": self.publisher,
            "name": self.name,
            "displayName": self.display_name,
            "version": self.version,
            "editor": self.editor,
            "installSource": self.install_source,
            "packageSha256": self.package_sha256,
            "manifestPath": self.manifest_path,
            "activationEvents": list(self.activation_events),
            "fileCount": self.file_count,
            "totalSize": self.total_size,
            "risk": {"label": self.risk_label, "score": self.risk_score},
            "domains": list(self.domains),
            "nativeBinaries": list(self.native_binaries),
            "scanWarnings": self.scan_warnings,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def inventory_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "extensionId": self.extension_id,
            "publisher": self.publisher,
            "name": self.name,
            "displayName": self.display_name,
            "version": self.version,
            "editor": self.editor,
            "installSource": self.install_source,
            "risk": self.risk_label,
            "riskScore": self.risk_score,
            "highestSeverity": self.highest_severity,
            "findingCount": len(self.findings),
            "domainCount": len(self.domains),
            "nativeBinaryCount": len(self.native_binaries),
            "activationEvents": list(self.activation_events),
            "target": self.target,
            "sha256": self.package_sha256,
        }


@dataclass
class DiffReport:
    old: ScanReport
    new: ScanReport
    added_findings: list[Finding]
    removed_findings: list[Finding]
    added_domains: tuple[str, ...]
    removed_domains: tuple[str, ...]
    added_native_binaries: tuple[str, ...]
    removed_native_binaries: tuple[str, ...]
    activation_changed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "old": self.old.to_dict(),
            "new": self.new.to_dict(),
            "activationChanged": self.activation_changed,
            "addedDomains": list(self.added_domains),
            "removedDomains": list(self.removed_domains),
            "addedNativeBinaries": list(self.added_native_binaries),
            "removedNativeBinaries": list(self.removed_native_binaries),
            "addedFindings": [finding.to_dict() for finding in self.added_findings],
            "removedFindings": [finding.to_dict() for finding in self.removed_findings],
        }


@dataclass(frozen=True)
class PolicyViolation:
    rule_id: str
    message: str
    severity: str
    extension_id: str
    target: str = ""
    detail: str = ""
    path: str = ""
    domain: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "extensionId": self.extension_id,
            "target": self.target,
            "detail": self.detail,
            "path": self.path,
            "domain": self.domain,
        }
