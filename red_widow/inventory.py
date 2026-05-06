from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .gate import GateReport
from .models import SCHEMA_VERSION
from .output import inventory_markdown, inventory_text


@dataclass(frozen=True)
class InventoryReport:
    gate: GateReport
    generated_at: str

    @property
    def summary(self) -> dict[str, int]:
        gate_summary = self.gate.summary
        return {
            "extensions": len(self.gate.reports),
            "recommendations": len(self.gate.recommendations),
            "marketplacePackages": len(self.gate.marketplace_packages),
            "aiIdeItems": len(self.gate.info_items) + len(self.gate.blocking_items) + len(self.gate.review_items),
            "blockingItems": gate_summary["blockingItems"],
            "reviewItems": gate_summary["reviewItems"],
            "scanErrors": len(self.gate.scan_errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": self.generated_at,
            "summary": self.summary,
            "extensions": [report.inventory_dict() for report in self.gate.reports],
            "recommendations": [recommendation.to_dict() for recommendation in self.gate.recommendations],
            "marketplacePackages": [package.to_dict() for package in self.gate.marketplace_packages],
            "aiIdeItems": {
                "info": [item.to_dict() for item in self.gate.info_items],
                "blocking": [item.to_dict() for item in self.gate.blocking_items],
                "review": [item.to_dict() for item in self.gate.review_items],
            },
            "policyViolations": [violation.to_dict() for violation in self.gate.policy_violations],
            "lockfileErrors": self.gate.lockfile_errors,
            "scanErrors": self.gate.scan_errors,
            "gate": {
                "decision": self.gate.decision,
                "reason": self.gate.reason,
                "shouldBlock": self.gate.should_block,
                "hasReview": self.gate.has_review,
            },
        }


def make_inventory_report(gate: GateReport, *, generated_at: str | None = None) -> InventoryReport:
    return InventoryReport(
        gate=gate,
        generated_at=generated_at or _utc_timestamp(),
    )


def inventory_report_text(report: InventoryReport) -> str:
    summary = report.summary
    lines = [
        "Red Widow inventory",
        f"Generated: {report.generated_at}",
        (
            "Summary: "
            f"{summary['extensions']} extension(s), "
            f"{summary['recommendations']} recommendation(s), "
            f"{summary['aiIdeItems']} AI IDE item(s), "
            f"{summary['blockingItems']} blocking item(s), "
            f"{summary['reviewItems']} review item(s), "
            f"{summary['scanErrors']} scan error(s)"
        ),
        "",
        "Extensions:",
    ]
    lines.append(inventory_text(report.gate.reports).rstrip() if report.gate.reports else "none")
    _append_items(lines, "Blocking AI IDE items", report.gate.blocking_items)
    _append_items(lines, "Review AI IDE items", report.gate.review_items)
    _append_items(lines, "Informational AI IDE items", report.gate.info_items)
    if report.gate.scan_errors:
        lines.extend(["", "Scan errors:"])
        for error in report.gate.scan_errors:
            lines.append(f"  - {error['target']}: {error['error']}")
    return "\n".join(lines).rstrip() + "\n"


def inventory_report_markdown(report: InventoryReport) -> str:
    summary = report.summary
    lines = [
        "# Red Widow inventory",
        "",
        f"Generated: `{report.generated_at}`",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Extensions | {summary['extensions']} |",
        f"| Recommendations | {summary['recommendations']} |",
        f"| Marketplace packages | {summary['marketplacePackages']} |",
        f"| AI IDE items | {summary['aiIdeItems']} |",
        f"| Blocking items | {summary['blockingItems']} |",
        f"| Review items | {summary['reviewItems']} |",
        f"| Scan errors | {summary['scanErrors']} |",
        "",
        "## Extensions",
        "",
    ]
    lines.append(inventory_markdown(report.gate.reports).rstrip() if report.gate.reports else "none")
    _append_markdown_items(lines, "Blocking AI IDE items", report.gate.blocking_items)
    _append_markdown_items(lines, "Review AI IDE items", report.gate.review_items)
    _append_markdown_items(lines, "Informational AI IDE items", report.gate.info_items)
    if report.gate.scan_errors:
        lines.extend(["", "## Scan errors", ""])
        for error in report.gate.scan_errors:
            lines.append(f"- `{_escape_md(error['target'])}`: {_escape_md(error['error'])}")
    return "\n".join(lines).rstrip() + "\n"


def _append_items(lines: list[str], title: str, items: list[Any]) -> None:
    if not items:
        return
    lines.extend(["", f"{title}:"])
    for item in items:
        detail = f" - {item.detail}" if item.detail else ""
        target = f" ({item.target})" if item.target else ""
        lines.append(f"  [{item.severity.upper()}] {item.rule_id}: {item.message}{target}{detail}")


def _append_markdown_items(lines: list[str], title: str, items: list[Any]) -> None:
    if not items:
        return
    lines.extend(
        [
            "",
            f"## {title}",
            "",
            "| Severity | Rule | Message | Target | Detail |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_md(item.severity.upper()),
                    _escape_md(item.rule_id),
                    _escape_md(item.message),
                    _escape_md(item.target),
                    _escape_md(item.detail),
                ]
            )
            + " |"
        )


def _escape_md(value: str) -> str:
    return value.replace("|", "\\|")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
