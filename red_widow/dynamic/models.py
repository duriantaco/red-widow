from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import SCHEMA_VERSION, ScanReport, SEVERITY_ORDER


@dataclass(frozen=True)
class DynamicEvent:
    kind: str
    operation: str
    target: str = ""
    detail: str = ""
    canary: bool = False
    blocked: bool = False

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> DynamicEvent:
        return cls(
            kind=str(payload.get("kind", "")),
            operation=str(payload.get("operation", "")),
            target=str(payload.get("target", "")),
            detail=str(payload.get("detail", "")),
            canary=bool(payload.get("canary", False)),
            blocked=bool(payload.get("blocked", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "operation": self.operation,
            "target": self.target,
            "detail": self.detail,
            "canary": self.canary,
            "blocked": self.blocked,
        }


@dataclass(frozen=True)
class DynamicViolation:
    rule_id: str
    title: str
    severity: str
    detail: str = ""
    evidence: tuple[str, ...] = ()
    blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": list(self.evidence),
            "blocking": self.blocking,
        }


@dataclass
class DynamicRunReport:
    target: str
    scan: ScanReport
    run_dir: str
    workspace_dir: str
    extension_dir: str
    canary_marker: str
    events: list[DynamicEvent] = field(default_factory=list)
    violations: list[DynamicViolation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    harness_exit_code: int = 0
    timed_out: bool = False

    @property
    def highest_severity(self) -> str:
        if not self.violations:
            return "info"
        return max(self.violations, key=lambda item: SEVERITY_ORDER.get(item.severity, 0)).severity

    @property
    def should_block(self) -> bool:
        return any(violation.blocking for violation in self.violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "target": self.target,
            "extension": self.scan.inventory_dict(),
            "runDir": self.run_dir,
            "workspaceDir": self.workspace_dir,
            "extensionDir": self.extension_dir,
            "canaryMarker": self.canary_marker,
            "events": [event.to_dict() for event in self.events],
            "violations": [violation.to_dict() for violation in self.violations],
            "errors": self.errors,
            "harnessExitCode": self.harness_exit_code,
            "timedOut": self.timed_out,
            "highestSeverity": self.highest_severity,
            "shouldBlock": self.should_block,
        }
