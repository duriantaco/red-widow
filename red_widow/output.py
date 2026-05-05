from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Finding, PolicyViolation, SCHEMA_VERSION, ScanReport


def inventory_markdown(reports: list[ScanReport]) -> str:
    lines = [
        "| Extension | Version | Editor | Source | Risk | Findings | Domains | Native | Target |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for report in sorted(reports, key=lambda item: item.extension_id):
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_md(report.extension_id),
                    _escape_md(report.version or ""),
                    _escape_md(report.editor or ""),
                    _escape_md(report.install_source or ""),
                    report.risk_label,
                    str(len(report.findings)),
                    str(len(report.domains)),
                    str(len(report.native_binaries)),
                    _escape_md(report.target),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def inventory_text(reports: list[ScanReport]) -> str:
    rows = [
        [
            report.extension_id,
            report.version or "",
            report.editor or "",
            report.install_source or "",
            report.risk_label,
            str(len(report.findings)),
            str(len(report.domains)),
            str(len(report.native_binaries)),
            report.target,
        ]
        for report in sorted(reports, key=lambda item: item.extension_id)
    ]
    headers = ["Extension", "Version", "Editor", "Source", "Risk", "Find", "Domains", "Native", "Target"]
    widths = [
        min(max(len(row[index]) for row in rows + [headers]), 120 if index == 8 else 52 if index == 0 else 16)
        for index in range(len(headers))
    ]
    output = [_format_row(headers, widths), _format_row(["-" * width for width in widths], widths)]
    output.extend(_format_row(row, widths) for row in rows)
    return "\n".join(output) + "\n"


def sarif_report(reports: list[ScanReport], violations: list[PolicyViolation]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for report in reports:
        for finding in report.findings:
            rule_id = f"red-widow.{finding.rule_id}"
            rules.setdefault(rule_id, _sarif_rule(rule_id, finding.title, finding.severity))
            results.append(_finding_result(report, finding, rule_id))

    for violation in violations:
        rule_id = f"red-widow.policy.{violation.rule_id}"
        rules.setdefault(rule_id, _sarif_rule(rule_id, violation.message, violation.severity))
        results.append(_violation_result(violation, rule_id))

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "red-widow",
                        "informationUri": "https://github.com/local/red-widow",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {"schemaVersion": SCHEMA_VERSION},
                "results": results,
            }
        ],
    }


def _format_row(values: list[str], widths: list[int]) -> str:
    cells = []
    for value, width in zip(values, widths):
        text = value if len(value) <= width else value[: width - 1] + "."
        cells.append(text.ljust(width))
    return "  ".join(cells).rstrip()


def _sarif_rule(rule_id: str, title: str, severity: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": title},
        "defaultConfiguration": {"level": _sarif_level(severity)},
    }


def _finding_result(report: ScanReport, finding: Finding, rule_id: str) -> dict[str, Any]:
    uri = _artifact_uri(report, finding.path)
    return {
        "ruleId": rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": _message(finding.title, finding.detail, finding.evidence)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "properties": {
            "schemaVersion": SCHEMA_VERSION,
            "extensionId": report.extension_id,
            "target": report.target,
            "internalPath": finding.path,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "blocking": bool(finding.blocking),
            "category": finding.category,
            "scope": finding.scope,
            "remediation": finding.remediation,
        },
    }


def _violation_result(violation: PolicyViolation, rule_id: str) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": _sarif_level(violation.severity),
        "message": {"text": _message(violation.message, violation.detail, ())},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": _path_uri(violation.target)}}}
        ],
        "properties": {
            "schemaVersion": SCHEMA_VERSION,
            "extensionId": violation.extension_id,
            "target": violation.target,
            "severity": violation.severity,
            "path": violation.path,
            "domain": violation.domain,
        },
    }


def _artifact_uri(report: ScanReport, internal_path: str) -> str:
    target = Path(report.target)
    if target.is_dir() and internal_path:
        return _path_uri(str(target / internal_path))
    if internal_path:
        return f"{_path_uri(report.target)}#{internal_path}"
    return _path_uri(report.target)


def _path_uri(path: str) -> str:
    return Path(path).as_posix()


def _message(title: str, detail: str, evidence: tuple[str, ...]) -> str:
    parts = [title]
    if detail:
        parts.append(detail)
    if evidence:
        parts.extend(evidence)
    return " - ".join(parts)


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _escape_md(value: str) -> str:
    return value.replace("|", "\\|")
