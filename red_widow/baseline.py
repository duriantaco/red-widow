from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding, PolicyViolation, ScanReport


def load_baseline(path: str | Path) -> dict[str, Any]:
    baseline_path = Path(path).expanduser()
    with baseline_path.open("r", encoding="utf-8") as fh:
        baseline = json.load(fh)
    if not isinstance(baseline, dict):
        raise ValueError("baseline file must contain a JSON object")
    return baseline


def make_baseline(
    reports: list[ScanReport], violations: list[PolicyViolation] | None = None
) -> dict[str, Any]:
    return {
        "findings": [_finding_record(report, finding) for report in reports for finding in report.findings],
        "policyViolations": [
            _violation_record(violation) for violation in (violations or [])
        ],
    }


def apply_finding_baseline(reports: list[ScanReport], baseline: dict[str, Any]) -> int:
    allowed = {_record_key(item) for item in _dict_list(baseline.get("findings"))}
    if not allowed:
        return 0

    suppressed = 0
    for report in reports:
        kept: list[Finding] = []
        for finding in report.findings:
            if _record_key(_finding_record(report, finding)) in allowed:
                suppressed += 1
            else:
                kept.append(finding)
        report.findings = kept
    return suppressed


def filter_policy_violations(
    violations: list[PolicyViolation], baseline: dict[str, Any]
) -> tuple[list[PolicyViolation], int]:
    allowed = {_record_key(item) for item in _dict_list(baseline.get("policyViolations"))}
    if not allowed:
        return violations, 0

    kept: list[PolicyViolation] = []
    suppressed = 0
    for violation in violations:
        if _record_key(_violation_record(violation)) in allowed:
            suppressed += 1
        else:
            kept.append(violation)
    return kept, suppressed


def _finding_record(report: ScanReport, finding: Finding) -> dict[str, str]:
    return {
        "extensionId": report.extension_id,
        "ruleId": finding.rule_id,
        "path": finding.path,
        "detail": finding.detail,
        "scope": finding.scope,
    }


def _violation_record(violation: PolicyViolation) -> dict[str, str]:
    return {
        "extensionId": violation.extension_id,
        "ruleId": violation.rule_id,
        "detail": violation.detail,
        "path": violation.path,
        "domain": violation.domain,
    }


def _record_key(record: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(record.get("extensionId", "")),
        str(record.get("ruleId", "")),
        str(record.get("path", "")),
        str(record.get("domain", "")),
        str(record.get("detail", "")),
    )


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
