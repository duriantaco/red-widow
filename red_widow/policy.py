from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

from .models import Finding, PolicyViolation, SEVERITY_ORDER, SEVERITY_WEIGHTS, CONFIDENCE_WEIGHTS, ScanReport


def load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path).expanduser()
    with policy_path.open("r", encoding="utf-8") as fh:
        policy = json.load(fh)
    if not isinstance(policy, dict):
        raise ValueError("policy file must contain a JSON object")
    return policy


def evaluate_policy(reports: list[ScanReport], policy: dict[str, Any]) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for report in reports:
        violations.extend(_evaluate_report(report, policy))
    return sorted(
        violations,
        key=lambda violation: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(violation.severity, 5),
            violation.extension_id,
            violation.rule_id,
        ),
    )


def _evaluate_report(report: ScanReport, policy: dict[str, Any]) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    extension = report.extension_id
    exceptions = _dict_list(policy.get("exceptions"))
    findings = [
        finding for finding in report.findings if not _is_finding_excepted(report, finding, exceptions)
    ]

    allow_extensions = _string_list(policy.get("allowExtensions"))
    if allow_extensions and not _matches_any(extension, allow_extensions):
        violations.append(
            _violation(
                "extension-not-allowed",
                report,
                "high",
                f"{extension} is not in allowExtensions",
            )
        )

    if _matches_any(extension, _string_list(policy.get("blockExtensions"))):
        violations.append(
            _violation("extension-blocked", report, "critical", f"{extension} is blocked")
        )

    allow_publishers = _string_list(policy.get("allowPublishers"))
    if allow_publishers and not _matches_any(report.publisher, allow_publishers):
        violations.append(
            _violation(
                "publisher-not-allowed",
                report,
                "high",
                f"{report.publisher or '<unknown>'} is not in allowPublishers",
            )
        )

    if _matches_any(report.publisher, _string_list(policy.get("blockPublishers"))):
        violations.append(
            _violation(
                "publisher-blocked",
                report,
                "critical",
                f"{report.publisher or '<unknown>'} is blocked",
            )
        )

    max_severity = policy.get("maxSeverity")
    highest_severity = _highest_severity(findings)
    if isinstance(max_severity, str) and _severity_above(highest_severity, max_severity):
        violations.append(
            _violation(
                "max-severity-exceeded",
                report,
                highest_severity,
                f"highest finding severity is {highest_severity}; policy max is {max_severity}",
            )
        )

    max_risk_score = policy.get("maxRiskScore")
    risk_score = _risk_score(findings)
    if isinstance(max_risk_score, int) and risk_score > max_risk_score:
        violations.append(
            _violation(
                "max-risk-score-exceeded",
                report,
                "high",
                f"risk score {risk_score} exceeds maxRiskScore {max_risk_score}",
            )
        )

    if policy.get("allowActivationStar") is False and "*" in report.activation_events:
        violations.append(
            _violation("activation-star-denied", report, "medium", "activationEvents contains '*'")
        )

    native_paths = [finding.path for finding in findings if finding.rule_id == "native-binary"]
    if policy.get("allowNativeBinaries") is False and native_paths:
        violations.append(
            _violation(
                "native-binaries-denied",
                report,
                "high",
                ", ".join(native_paths[:5]),
                path=native_paths[0],
            )
        )

    deny_findings = set(_string_list(policy.get("denyFindings")))
    for finding in findings:
        if finding.rule_id in deny_findings:
            violations.append(
                _violation(
                    "finding-denied",
                    report,
                    finding.severity,
                    f"{finding.rule_id}: {finding.title} {finding.path}".strip(),
                    path=finding.path,
                )
            )

    allow_domains = _string_list(policy.get("allowDomains"))
    block_domains = _string_list(policy.get("blockDomains"))
    for domain in report.domains:
        if allow_domains and not _matches_any(domain, allow_domains):
            violations.append(
                _violation(
                    "domain-not-allowed",
                    report,
                    "medium",
                    f"{domain} is not in allowDomains",
                    domain=domain,
                )
            )
        if _matches_any(domain, block_domains):
            violations.append(
                _violation("domain-blocked", report, "high", f"{domain} is blocked", domain=domain)
            )

    return [
        violation
        for violation in violations
        if not _is_violation_excepted(report, violation, exceptions)
    ]


def _violation(
    rule_id: str,
    report: ScanReport,
    severity: str,
    detail: str,
    path: str = "",
    domain: str = "",
) -> PolicyViolation:
    return PolicyViolation(
        rule_id=rule_id,
        message=f"{report.extension_id}: {rule_id.replace('-', ' ')}",
        severity=severity,
        extension_id=report.extension_id,
        target=report.target,
        detail=detail,
        path=path,
        domain=domain,
    )


def _severity_above(value: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(value.lower(), 0) > SEVERITY_ORDER.get(threshold.lower(), 0)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _matches_any(value: str, patterns: list[str]) -> bool:
    if not value:
        return False
    normalized = value.lower()
    return any(fnmatch.fnmatchcase(normalized, pattern.lower()) for pattern in patterns)


def _is_finding_excepted(
    report: ScanReport, finding: Finding, exceptions: list[dict[str, Any]]
) -> bool:
    for exception in exceptions:
        if not _exception_matches_report(report, exception):
            continue
        rule = exception.get("ruleId")
        if isinstance(rule, str) and not _matches_any(finding.rule_id, [rule]):
            continue
        path = exception.get("path")
        if isinstance(path, str) and not _matches_any(finding.path, [path]):
            continue
        scope = exception.get("scope")
        if isinstance(scope, str) and not _matches_any(finding.scope, [scope]):
            continue
        return True
    return False


def _is_violation_excepted(
    report: ScanReport, violation: PolicyViolation, exceptions: list[dict[str, Any]]
) -> bool:
    for exception in exceptions:
        if not _exception_matches_report(report, exception):
            continue
        rule = exception.get("ruleId")
        if isinstance(rule, str) and not _matches_any(violation.rule_id, [rule]):
            continue
        path = exception.get("path")
        if isinstance(path, str) and not _matches_any(violation.path, [path]):
            continue
        domain = exception.get("domain")
        if isinstance(domain, str) and not _matches_any(violation.domain, [domain]):
            continue
        return True
    return False


def _exception_matches_report(report: ScanReport, exception: dict[str, Any]) -> bool:
    extension = exception.get("extension")
    if isinstance(extension, str) and not _matches_any(report.extension_id, [extension]):
        return False
    publisher = exception.get("publisher")
    if isinstance(publisher, str) and not _matches_any(report.publisher, [publisher]):
        return False
    version = exception.get("version")
    if isinstance(version, str) and not _matches_any(report.version, [version]):
        return False
    return True


def _highest_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0)).severity


def _risk_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        base = SEVERITY_WEIGHTS.get(finding.severity, 0)
        confidence = CONFIDENCE_WEIGHTS.get(finding.confidence, 0.7)
        blocking = 1.0 if finding.blocking else 0.6
        score += round(base * confidence * blocking)
    return score
