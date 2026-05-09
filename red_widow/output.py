from __future__ import annotations

from pathlib import Path
from typing import Any

from .messages import GATE_INTENT, gate_next_action
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


def gate_markdown(report: Any) -> str:
    summary = report.summary
    lines = [
        "# Red Widow gate",
        "",
        GATE_INTENT,
        "",
        f"Decision: **{_escape_md(report.decision)}** - {_escape_md(report.reason)}",
        "",
        f"Next: {_escape_md(gate_next_action(report))}",
    ]
    if getattr(report, "inspected", None):
        lines.extend(["", f"Inspected: {_escape_md('; '.join(report.inspected))}"])
    if getattr(report, "skipped", None):
        lines.extend(["", f"Skipped: {_escape_md('; '.join(report.skipped))}"])
    lines.extend(
        [
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Scanned packages | {summary['scannedPackages']} |",
            f"| Recommendations | {summary['recommendations']} |",
            f"| Marketplace packages | {summary['marketplacePackages']} |",
            f"| Info items | {summary.get('infoItems', 0)} |",
            f"| Blocking items | {summary['blockingItems']} |",
            f"| Review items | {summary['reviewItems']} |",
            f"| Scan errors | {summary['scanErrors']} |",
            "",
        ]
    )

    blocking_items = [
        *report.blocking_items,
        *_policy_items(report.policy_violations),
        *_lockfile_items(report.lockfile_errors),
        *_finding_items(report.reports, blocking=True),
    ]
    review_items = [
        *report.review_items,
        *_finding_items(report.reports, blocking=False),
    ]

    if blocking_items:
        lines.extend(_gate_item_markdown("Blocking items", blocking_items))
    if report.info_items:
        lines.extend(_gate_item_markdown("AI IDE workflow items", report.info_items))
    if review_items:
        lines.extend(_gate_item_markdown("Review items", review_items))
    if report.reports:
        lines.extend(["## Extension inventory", "", inventory_markdown(report.reports).rstrip(), ""])
    if report.scan_errors:
        lines.extend(["## Scan errors", ""])
        for error in report.scan_errors:
            lines.append(f"- `{_escape_md(error['target'])}`: {_escape_md(error['error'])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def gate_sarif_report(report: Any) -> dict[str, Any]:
    payload = sarif_report(report.reports, report.policy_violations)
    run = payload["runs"][0]
    driver = run["tool"]["driver"]
    existing_rules = {rule["id"]: rule for rule in driver["rules"]}

    def add_rule(rule_id: str, title: str, severity: str) -> None:
        existing_rules.setdefault(rule_id, _sarif_rule(rule_id, title, severity))

    for item in [*report.info_items, *report.blocking_items, *report.review_items]:
        rule_id = f"red-widow.gate.{item.rule_id}"
        add_rule(rule_id, item.message, item.severity)
        run["results"].append(_gate_item_result(item, rule_id))

    for error in report.lockfile_errors:
        rule_id = "red-widow.gate.lockfile"
        add_rule(rule_id, "Red Widow lockfile violation", "high")
        run["results"].append(_plain_gate_result(rule_id, "error", error, "red-widow.lock.json"))

    for error in report.scan_errors:
        rule_id = "red-widow.gate.scan-error"
        add_rule(rule_id, "Red Widow scan error", "medium")
        run["results"].append(
            _plain_gate_result(rule_id, "warning", error["error"], error.get("target", "red-widow-gate"))
        )

    driver["rules"] = list(existing_rules.values())
    run.setdefault("properties", {})["gateDecision"] = report.decision
    run["properties"]["gateSummary"] = report.summary
    return payload


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


def _gate_item_result(item: Any, rule_id: str) -> dict[str, Any]:
    uri = item.target or item.extension_id or "red-widow-gate"
    return {
        "ruleId": rule_id,
        "level": _sarif_level(item.severity),
        "message": {"text": _message(item.message, item.detail, ())},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _path_uri(uri)}}}],
        "properties": {
            "schemaVersion": SCHEMA_VERSION,
            "severity": item.severity,
            "extensionId": item.extension_id,
            "target": item.target,
            "blocking": bool(item.blocking),
            "source": "gate",
        },
    }


def _plain_gate_result(rule_id: str, level: str, message: str, uri: str) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _path_uri(uri)}}}],
        "properties": {"schemaVersion": SCHEMA_VERSION, "source": "gate"},
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


def _gate_item_markdown(title: str, items: list[Any]) -> list[str]:
    lines = [
        f"## {title}",
        "",
        "| Severity | Rule | Message | Target | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_md(str(getattr(item, "severity", ""))).upper(),
                    _escape_md(str(getattr(item, "rule_id", ""))),
                    _escape_md(str(getattr(item, "message", ""))),
                    _escape_md(str(getattr(item, "target", ""))),
                    _escape_md(str(getattr(item, "detail", ""))),
                ]
            )
            + " |"
        )
    lines.append("")
    return lines


def _policy_items(violations: list[PolicyViolation]) -> list[Any]:
    from types import SimpleNamespace

    return [
        SimpleNamespace(
            rule_id=f"policy.{violation.rule_id}",
            message=violation.message,
            severity=violation.severity,
            target=violation.target,
            detail=violation.detail,
        )
        for violation in violations
    ]


def _lockfile_items(errors: list[str]) -> list[Any]:
    from types import SimpleNamespace

    return [
        SimpleNamespace(
            rule_id="lockfile",
            message="Lockfile validation failed",
            severity="high",
            target="red-widow.lock.json",
            detail=error,
        )
        for error in errors
    ]


def _finding_items(reports: list[ScanReport], *, blocking: bool) -> list[Any]:
    from types import SimpleNamespace

    items: list[Any] = []
    for report in reports:
        for finding in report.findings:
            if bool(finding.blocking) != blocking:
                continue
            items.append(
                SimpleNamespace(
                    rule_id=finding.rule_id,
                    message=f"{report.extension_id}: {finding.title}",
                    severity=finding.severity,
                    target=finding.path or report.target,
                    detail=finding.detail,
                )
            )
    return items
