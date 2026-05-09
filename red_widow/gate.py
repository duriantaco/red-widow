from __future__ import annotations

import fnmatch
import json
import subprocess
from contextlib import suppress
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from .ai_ide import AiIdeItem, scan_ai_ide_workflow
from .marketplace import MarketplaceError, MarketplacePackage, resolve_marketplace_recommendations
from .models import PolicyViolation, SCHEMA_VERSION, ScanReport
from .policy import evaluate_policy
from .scanner import discover_installed_extensions, scan_target, validate_lockfile


WORKSPACE_SCAN_SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".red-widow",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}
RECOMMENDATIONS_KIND = "recommendations"
UNWANTED_RECOMMENDATIONS_KIND = "unwantedRecommendations"
RECOMMENDATION_KINDS = (RECOMMENDATIONS_KIND, UNWANTED_RECOMMENDATIONS_KIND)


@dataclass(frozen=True)
class ExtensionRecommendation:
    extension_id: str
    path: str
    kind: str = "recommendation"
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "extensionId": self.extension_id,
            "path": self.path,
            "kind": self.kind,
            "resolved": self.resolved,
        }


@dataclass(frozen=True)
class GateItem:
    rule_id: str
    message: str
    severity: str
    extension_id: str = ""
    target: str = ""
    detail: str = ""
    blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "extensionId": self.extension_id,
            "target": self.target,
            "detail": self.detail,
            "blocking": self.blocking,
        }


@dataclass
class GateReport:
    reports: list[ScanReport] = field(default_factory=list)
    recommendations: list[ExtensionRecommendation] = field(default_factory=list)
    policy_violations: list[PolicyViolation] = field(default_factory=list)
    lockfile_errors: list[str] = field(default_factory=list)
    scan_errors: list[dict[str, str]] = field(default_factory=list)
    marketplace_packages: list[MarketplacePackage] = field(default_factory=list)
    marketplace_errors: list[MarketplaceError] = field(default_factory=list)
    info_items: list[GateItem] = field(default_factory=list)
    blocking_items: list[GateItem] = field(default_factory=list)
    review_items: list[GateItem] = field(default_factory=list)
    inspected: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        if self.blocking_items or self.policy_violations or self.lockfile_errors:
            return True
        return any(any(finding.blocking for finding in report.findings) for report in self.reports)

    @property
    def has_review(self) -> bool:
        if self.scan_errors or self.review_items:
            return True
        return any(any(not finding.blocking for finding in report.findings) for report in self.reports)

    @property
    def decision(self) -> str:
        if self.should_block:
            return "BLOCK"
        if self.has_review:
            return "REVIEW"
        return "PASS"

    @property
    def reason(self) -> str:
        if self.should_block:
            return "blocking IDE extension risk found"
        if self.scan_errors:
            return "scan coverage incomplete"
        if self.has_review:
            return "IDE extension trust changes need review"
        return "no IDE extension gate issues found"

    @property
    def summary(self) -> dict[str, int]:
        blocking_findings = sum(
            1 for report in self.reports for finding in report.findings if finding.blocking
        )
        review_findings = sum(
            1 for report in self.reports for finding in report.findings if not finding.blocking
        )
        return {
            "scannedPackages": len(self.reports),
            "recommendations": len(self.recommendations),
            "marketplacePackages": len(self.marketplace_packages),
            "marketplaceErrors": len(self.marketplace_errors),
            "infoItems": len(self.info_items),
            "blockingItems": len(self.blocking_items) + len(self.policy_violations) + len(self.lockfile_errors) + blocking_findings,
            "reviewItems": len(self.review_items) + review_findings,
            "scanErrors": len(self.scan_errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "decision": self.decision,
            "reason": self.reason,
            "shouldBlock": self.should_block,
            "hasReview": self.has_review,
            "summary": self.summary,
            "reports": [report.to_dict() for report in self.reports],
            "recommendations": [recommendation.to_dict() for recommendation in self.recommendations],
            "marketplacePackages": [package.to_dict() for package in self.marketplace_packages],
            "marketplaceErrors": [error.to_dict() for error in self.marketplace_errors],
            "policyViolations": [violation.to_dict() for violation in self.policy_violations],
            "lockfileErrors": self.lockfile_errors,
            "scanErrors": self.scan_errors,
            "infoItems": [item.to_dict() for item in self.info_items],
            "blockingItems": [item.to_dict() for item in self.blocking_items],
            "reviewItems": [item.to_dict() for item in self.review_items],
            "inspected": self.inspected,
            "skipped": self.skipped,
        }


@dataclass(frozen=True)
class _GateInputs:
    targets: list[Path]
    workspaces: list[Path]
    recommendations: list[Path]
    extension_roots: list[Path]


@dataclass(frozen=True)
class _MarketplaceResolutionOptions:
    policy: dict[str, Any]
    lockfile: dict[str, Any]
    offline: bool
    workspaces: list[Path]
    cache_dir: str | Path | None
    continue_on_error: bool


@dataclass(frozen=True)
class _IgnoreRule:
    base: str
    pattern: str
    negated: bool = False
    directory_only: bool = False
    anchored: bool = False
    has_slash: bool = False


def run_gate(
    targets: Iterable[str | Path] = (),
    workspaces: Iterable[str | Path] = (),
    recommendation_paths: Iterable[str | Path] = (),
    installed: bool = False,
    extension_roots: Iterable[str | Path] = (),
    policy: dict[str, Any] | None = None,
    lockfile: dict[str, Any] | None = None,
    offline: bool = False,
    marketplace_cache_dir: str | Path | None = None,
    continue_on_error: bool = True,
) -> GateReport:
    policy = policy or {}
    lockfile = lockfile or {}
    inputs = _normalize_gate_inputs(
        targets,
        workspaces,
        recommendation_paths,
        extension_roots,
        installed=installed,
    )
    scan_targets, installed_targets = _collect_gate_targets(inputs, installed=installed)

    report = GateReport()
    _set_gate_scope(report, inputs, installed=installed, offline=offline)
    _scan_gate_targets(
        report,
        scan_targets,
        installed_targets,
        inputs.extension_roots,
        continue_on_error=continue_on_error,
    )

    recommendations = _load_recommendations(inputs.workspaces, inputs.recommendations)
    _set_recommendations(report, recommendations, lockfile)

    marketplace_candidates = _marketplace_candidate_ids(report, policy, lockfile)
    _set_marketplace_scope(report, marketplace_candidates, offline=offline)
    _resolve_gate_marketplace_packages(
        report,
        recommendations,
        _MarketplaceResolutionOptions(
            policy=policy,
            lockfile=lockfile,
            offline=offline,
            workspaces=inputs.workspaces,
            cache_dir=marketplace_cache_dir,
            continue_on_error=continue_on_error,
        ),
    )

    if policy:
        report.policy_violations = evaluate_policy(report.reports, policy)
    if lockfile:
        report.lockfile_errors = validate_lockfile(report.reports, lockfile)

    _add_ai_ide_items(report, _ai_ide_workspaces(inputs, installed=installed), include_global=installed)
    _add_recommendation_items(report, policy, lockfile, offline=offline)
    return report


def _set_gate_scope(report: GateReport, inputs: _GateInputs, *, installed: bool, offline: bool) -> None:
    inspected: list[str] = []
    skipped: list[str] = []

    if inputs.workspaces:
        inspected.extend(
            [
                "workspace extension recommendations",
                "non-ignored checked-in VSIX packages",
                "VS Code/Cursor/Windsurf MCP, tasks, settings, rules, hooks, and agent files",
            ]
        )
    if inputs.recommendations:
        inspected.append("explicit extension recommendation files")
    if inputs.targets:
        inspected.append("explicit VSIX or extension directory targets")
    if installed:
        inspected.append("installed VS Code-compatible extensions and global AI-IDE config")
    else:
        skipped.append("installed extensions and global AI-IDE config unless --installed is set")
    report.inspected = inspected
    report.skipped = skipped


def _set_marketplace_scope(report: GateReport, marketplace_candidates: list[str], *, offline: bool) -> None:
    if not marketplace_candidates:
        return
    if offline:
        report.skipped.append("marketplace package downloads because --offline is set")
    else:
        report.inspected.append("marketplace resolution for unresolved recommendations")


def _normalize_gate_inputs(
    targets: Iterable[str | Path],
    workspaces: Iterable[str | Path],
    recommendation_paths: Iterable[str | Path],
    extension_roots: Iterable[str | Path],
    *,
    installed: bool,
) -> _GateInputs:
    explicit_targets = [Path(target).expanduser() for target in targets]
    explicit_workspaces = [Path(workspace).expanduser() for workspace in workspaces]
    explicit_recommendations = [Path(path).expanduser() for path in recommendation_paths]
    extension_root_paths = [Path(root).expanduser() for root in extension_roots]

    if not explicit_targets and not explicit_workspaces and not explicit_recommendations and not installed:
        explicit_workspaces = [Path.cwd()]

    return _GateInputs(
        targets=explicit_targets,
        workspaces=explicit_workspaces,
        recommendations=explicit_recommendations,
        extension_roots=extension_root_paths,
    )


def _collect_gate_targets(inputs: _GateInputs, *, installed: bool) -> tuple[list[Path], list[Path]]:
    workspace_targets = _discover_workspace_vsix_targets(inputs.workspaces)
    scan_targets = _dedupe_paths([*inputs.targets, *workspace_targets])
    installed_targets: list[Path] = []
    if installed:
        installed_targets = discover_installed_extensions(inputs.extension_roots)
        scan_targets.extend(installed_targets)
    return scan_targets, installed_targets


def _scan_gate_targets(
    report: GateReport,
    scan_targets: list[Path],
    installed_targets: list[Path],
    extension_root_paths: list[Path],
    *,
    continue_on_error: bool,
) -> None:
    for target in scan_targets:
        try:
            scan_report = scan_target(target)
            _annotate_installed_scan(scan_report, installed_targets, extension_root_paths)
            report.reports.append(scan_report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if not continue_on_error:
                raise
            report.scan_errors.append({"target": str(target), "error": str(exc)})


def _resolve_gate_marketplace_packages(
    report: GateReport,
    recommendations: list[ExtensionRecommendation],
    options: _MarketplaceResolutionOptions,
) -> None:
    if options.offline:
        return

    marketplace_ids = _marketplace_candidate_ids(report, options.policy, options.lockfile)
    if not marketplace_ids:
        return

    packages, errors = resolve_marketplace_recommendations(
        marketplace_ids,
        cache_dir=options.cache_dir or _default_marketplace_cache_dir(options.workspaces),
    )
    report.marketplace_packages = packages
    report.marketplace_errors = errors
    _scan_marketplace_packages(report, packages, continue_on_error=options.continue_on_error)
    _set_recommendations(report, recommendations, options.lockfile)


def _scan_marketplace_packages(
    report: GateReport,
    packages: list[MarketplacePackage],
    *,
    continue_on_error: bool,
) -> None:
    for package in packages:
        try:
            scan_report = scan_target(package.path)
            scan_report.install_source = package.source
            report.reports.append(scan_report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if not continue_on_error:
                raise
            report.scan_errors.append({"target": package.path, "error": str(exc)})


def _set_recommendations(
    report: GateReport,
    recommendations: list[ExtensionRecommendation],
    lockfile: dict[str, Any] | None = None,
) -> None:
    resolved_ids = {scan.extension_id.lower() for scan in report.reports}
    resolved_ids.update(_allowed_lockfile_extensions(lockfile or {}))
    report.recommendations = [
        ExtensionRecommendation(
            extension_id=recommendation.extension_id,
            path=recommendation.path,
            kind=recommendation.kind,
            resolved=recommendation.extension_id.lower() in resolved_ids,
        )
        for recommendation in recommendations
    ]


def _marketplace_candidate_ids(
    report: GateReport,
    policy: dict[str, Any],
    lockfile: dict[str, Any],
) -> list[str]:
    allowed_lockfile = _allowed_lockfile_extensions(lockfile)
    candidates: list[str] = []
    for recommendation in report.recommendations:
        if recommendation.kind != RECOMMENDATIONS_KIND or recommendation.resolved:
            continue
        if recommendation.extension_id in allowed_lockfile:
            continue
        if _policy_item_for_recommendation(recommendation, policy):
            continue
        candidates.append(recommendation.extension_id)
    return sorted(set(candidates))


def _default_marketplace_cache_dir(workspaces: list[Path]) -> Path:
    root = workspaces[0] if workspaces else Path.cwd()
    return root / ".red-widow" / "cache" / "extensions"


def _discover_workspace_vsix_targets(workspaces: list[Path]) -> list[Path]:
    targets: list[Path] = []
    for workspace in workspaces:
        if not workspace.is_dir():
            continue
        candidates: list[Path] = []
        with suppress(OSError):
            iterator = workspace.rglob("*.vsix")
            for path in iterator:
                if not path.is_file() or _is_workspace_skip_dir_path(path, workspace):
                    continue
                candidates.append(path)
        ignored = _ignored_workspace_paths(candidates, workspace)
        targets.extend(
            path
            for path in candidates
            if _workspace_relative_posix(path, workspace) not in ignored
        )
    return sorted(targets)


def _is_workspace_skip_dir_path(path: Path, workspace: Path) -> bool:
    try:
        relative = path.relative_to(workspace)
    except ValueError:
        return True
    return any(part in WORKSPACE_SCAN_SKIP_DIRS for part in relative.parts)


def _ignored_workspace_paths(paths: list[Path], workspace: Path) -> set[str]:
    git_ignored = _git_check_ignored_paths(paths, workspace)
    if git_ignored is not None:
        return git_ignored
    return _fallback_ignored_workspace_paths(paths, workspace)


def _git_check_ignored_paths(paths: list[Path], workspace: Path) -> set[str] | None:
    if not paths:
        return set()
    relative_paths = [_workspace_relative_posix(path, workspace) for path in paths]
    try:
        completed = subprocess.run(
            ["git", "check-ignore", "--no-index", "--stdin"],
            cwd=workspace,
            input="\n".join(relative_paths) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if completed.returncode not in {0, 1}:
        return None
    return {line for line in completed.stdout.splitlines() if line}


def _fallback_ignored_workspace_paths(paths: list[Path], workspace: Path) -> set[str]:
    rules = _workspace_ignore_rules(str(workspace.expanduser().resolve(strict=False)))
    ignored: set[str] = set()
    for path in paths:
        relative = _workspace_relative_posix(path, workspace)
        if _fallback_path_ignored(relative, rules):
            ignored.add(relative)
    return ignored


@lru_cache(maxsize=128)
def _workspace_ignore_rules(workspace: str) -> tuple[_IgnoreRule, ...]:
    root = Path(workspace)
    ignore_files = [root / ".gitignore"]
    with suppress(OSError):
        for path in root.rglob(".gitignore"):
            if path == root / ".gitignore" or _is_workspace_skip_dir_path(path, root):
                continue
            ignore_files.append(path)

    rules: list[_IgnoreRule] = []
    for ignore_file in ignore_files:
        if not ignore_file.is_file():
            continue
        try:
            lines = ignore_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        base = ignore_file.parent.relative_to(root).as_posix()
        base = "" if base == "." else base
        for line in lines:
            rule = _parse_gitignore_rule(base, line)
            if rule:
                rules.append(rule)
    return tuple(rules)


def _parse_gitignore_rule(base: str, line: str) -> _IgnoreRule | None:
    pattern = line.strip()
    if not pattern or pattern.startswith("#"):
        return None
    if pattern.startswith("\\#") or pattern.startswith("\\!"):
        pattern = pattern[1:]

    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:].strip()
    if not pattern:
        return None

    directory_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    if not pattern:
        return None
    return _IgnoreRule(
        base=base,
        pattern=pattern,
        negated=negated,
        directory_only=directory_only,
        anchored=anchored,
        has_slash="/" in pattern,
    )


def _fallback_path_ignored(relative_posix: str, rules: tuple[_IgnoreRule, ...]) -> bool:
    ignored = False
    for rule in rules:
        if _ignore_rule_matches(relative_posix, rule):
            ignored = not rule.negated
    return ignored


def _ignore_rule_matches(relative_posix: str, rule: _IgnoreRule) -> bool:
    candidate = _relative_to_ignore_base(relative_posix, rule.base)
    if candidate is None:
        return False
    candidate_parts = candidate.split("/") if candidate else []
    pattern_parts = rule.pattern.split("/")
    if not candidate_parts:
        return False

    if rule.directory_only:
        directory_parts = candidate_parts[:-1]
        if rule.anchored or rule.has_slash:
            return any(
                _glob_segments_match(directory_parts[:index], pattern_parts)
                for index in range(1, len(directory_parts) + 1)
            )
        return any(fnmatch.fnmatchcase(part, rule.pattern) for part in directory_parts)

    if rule.anchored or rule.has_slash:
        return _glob_segments_match(candidate_parts, pattern_parts)
    return any(fnmatch.fnmatchcase(part, rule.pattern) for part in candidate_parts)


def _relative_to_ignore_base(relative_posix: str, base: str) -> str | None:
    if not base:
        return relative_posix
    if relative_posix == base:
        return ""
    prefix = base + "/"
    if not relative_posix.startswith(prefix):
        return None
    return relative_posix[len(prefix):]


def _glob_segments_match(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    if pattern_parts[0] == "**":
        return (
            _glob_segments_match(path_parts, pattern_parts[1:])
            or bool(path_parts and _glob_segments_match(path_parts[1:], pattern_parts))
        )
    if not path_parts:
        return False
    if not fnmatch.fnmatchcase(path_parts[0], pattern_parts[0]):
        return False
    return _glob_segments_match(path_parts[1:], pattern_parts[1:])


def _workspace_relative_posix(path: Path, workspace: Path) -> str:
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return path.as_posix()


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser().resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def _load_recommendations(
    workspaces: list[Path],
    recommendation_paths: list[Path],
) -> list[ExtensionRecommendation]:
    recommendations: list[ExtensionRecommendation] = []
    seen: set[tuple[str, str, str]] = set()
    for path in _recommendation_file_paths(workspaces, recommendation_paths):
        payload = _read_recommendations_file(path)
        for recommendation in _recommendations_from_payload(path, payload):
            key = (recommendation.extension_id, recommendation.path, recommendation.kind)
            if key in seen:
                continue
            seen.add(key)
            recommendations.append(recommendation)
    return recommendations


def _recommendation_file_paths(workspaces: list[Path], recommendation_paths: list[Path]) -> list[Path]:
    paths = [
        workspace / ".vscode" / "extensions.json"
        for workspace in workspaces
        if (workspace / ".vscode" / "extensions.json").is_file()
    ]
    for path in recommendation_paths:
        if not path.is_file():
            raise FileNotFoundError(f"recommendations file does not exist: {path}")
        paths.append(path)
    return paths


def _recommendations_from_payload(
    path: Path,
    payload: dict[str, Any],
) -> list[ExtensionRecommendation]:
    recommendations: list[ExtensionRecommendation] = []
    for kind in RECOMMENDATION_KINDS:
        values = payload.get(kind)
        if not isinstance(values, list):
            continue
        for value in values:
            extension_id = _recommendation_id(value)
            if extension_id:
                recommendations.append(
                    ExtensionRecommendation(extension_id=extension_id, path=str(path), kind=kind)
                )
    return recommendations


def _recommendation_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.strip().lower()


def _read_recommendations_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid recommendations JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: recommendations file must contain a JSON object")
    return payload


def _add_recommendation_items(
    report: GateReport,
    policy: dict[str, Any],
    lockfile: dict[str, Any],
    *,
    offline: bool,
) -> None:
    _add_recommendation_conflict_items(report)
    _add_unresolved_recommendation_items(report, policy, lockfile, offline=offline)


def _add_recommendation_conflict_items(report: GateReport) -> None:
    for path, extension_id in _conflicting_recommendations(report.recommendations):
        report.review_items.append(
            GateItem(
                rule_id="recommendation-conflict",
                message=f"{extension_id}: recommended and unwanted in the same VS Code recommendations file",
                severity="medium",
                extension_id=extension_id,
                target=path,
                detail="extension appears in recommendations and unwantedRecommendations",
                blocking=False,
            )
        )


def _conflicting_recommendations(
    recommendations: list[ExtensionRecommendation],
) -> list[tuple[str, str]]:
    by_recommendation: dict[tuple[str, str], set[str]] = {}
    for recommendation in recommendations:
        key = (recommendation.path, recommendation.extension_id)
        by_recommendation.setdefault(key, set()).add(recommendation.kind)
    return [
        key
        for key, kinds in by_recommendation.items()
        if RECOMMENDATIONS_KIND in kinds and UNWANTED_RECOMMENDATIONS_KIND in kinds
    ]


def _add_unresolved_recommendation_items(
    report: GateReport,
    policy: dict[str, Any],
    lockfile: dict[str, Any],
    *,
    offline: bool,
) -> None:
    resolved = {recommendation.extension_id for recommendation in report.recommendations if recommendation.resolved}
    allowed_lockfile = _allowed_lockfile_extensions(lockfile)
    marketplace_errors = {error.extension_id: error for error in report.marketplace_errors}
    for recommendation in report.recommendations:
        item = _unresolved_recommendation_item(
            recommendation,
            policy,
            allowed_lockfile,
            marketplace_errors,
            resolved,
            offline=offline,
        )
        if item:
            _append_gate_item(report, item)


def _unresolved_recommendation_item(
    recommendation: ExtensionRecommendation,
    policy: dict[str, Any],
    allowed_lockfile: set[str],
    marketplace_errors: dict[str, MarketplaceError],
    resolved: set[str],
    *,
    offline: bool,
) -> GateItem | None:
    if recommendation.kind != RECOMMENDATIONS_KIND or recommendation.extension_id in resolved:
        return None

    policy_item = _policy_item_for_recommendation(recommendation, policy)
    if policy_item:
        return policy_item
    if recommendation.extension_id in allowed_lockfile:
        return None

    error = marketplace_errors.get(recommendation.extension_id)
    if error:
        return GateItem(
            rule_id="marketplace-resolution-failed",
            message=f"{recommendation.extension_id}: marketplace package could not be resolved",
            severity="medium",
            extension_id=recommendation.extension_id,
            target=recommendation.path,
            detail=error.error,
            blocking=False,
        )

    detail = "offline mode did not fetch marketplace packages" if offline else "marketplace package was not resolved"
    return GateItem(
        rule_id="recommendation-unresolved",
        message=f"{recommendation.extension_id}: recommendation is not installed or locked locally",
        severity="medium",
        extension_id=recommendation.extension_id,
        target=recommendation.path,
        detail=detail,
        blocking=False,
    )


def _append_gate_item(report: GateReport, item: GateItem) -> None:
    if item.blocking:
        report.blocking_items.append(item)
    elif item.severity == "info":
        report.info_items.append(item)
    else:
        report.review_items.append(item)


def _add_ai_ide_items(
    report: GateReport,
    workspaces: list[Path],
    *,
    include_global: bool,
) -> None:
    for item in scan_ai_ide_workflow(workspaces, include_global=include_global):
        _append_gate_item(report, _gate_item_from_ai_ide(item))


def _ai_ide_workspaces(inputs: _GateInputs, *, installed: bool) -> list[Path]:
    if inputs.workspaces:
        return inputs.workspaces
    if installed:
        return [Path.cwd()]
    return []


def _gate_item_from_ai_ide(item: AiIdeItem) -> GateItem:
    return GateItem(
        rule_id=item.rule_id,
        message=item.message,
        severity=item.severity,
        target=item.target,
        detail=item.detail,
        blocking=item.blocking,
    )


def _policy_item_for_recommendation(
    recommendation: ExtensionRecommendation,
    policy: dict[str, Any],
) -> GateItem | None:
    extension_id = recommendation.extension_id
    if _matches_any(extension_id, _string_list(policy.get("blockExtensions"))):
        return GateItem(
            rule_id="recommendation-blocked",
            message=f"{extension_id}: recommended extension is blocked by policy",
            severity="critical",
            extension_id=extension_id,
            target=recommendation.path,
            detail="blockExtensions match",
            blocking=True,
        )

    allow_extensions = _string_list(policy.get("allowExtensions"))
    if allow_extensions and not _matches_any(extension_id, allow_extensions):
        return GateItem(
            rule_id="recommendation-not-allowed",
            message=f"{extension_id}: recommended extension is not allowed by policy",
            severity="high",
            extension_id=extension_id,
            target=recommendation.path,
            detail="allowExtensions does not match",
            blocking=True,
        )
    return None


def _allowed_lockfile_extensions(lockfile: dict[str, Any]) -> set[str]:
    allowed = lockfile.get("allowedExtensions")
    if not isinstance(allowed, dict):
        return set()
    return {str(extension_id).lower() for extension_id in allowed}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _matches_any(value: str, patterns: list[str]) -> bool:
    if not value:
        return False
    normalized = value.lower()
    return any(fnmatch.fnmatchcase(normalized, pattern.lower()) for pattern in patterns)


def _annotate_installed_scan(
    report: ScanReport,
    installed_targets: list[Path],
    custom_roots: list[Path],
) -> None:
    if not installed_targets:
        return
    target = _safe_resolve(Path(report.target))
    installed_paths = {_safe_resolve(path) for path in installed_targets}
    if target not in installed_paths:
        return
    if report.install_source == "directory":
        report.install_source = "installed"
    if not report.editor and any(_is_relative_to(target, _safe_resolve(root)) for root in custom_roots):
        report.editor = "Custom root"


def _safe_resolve(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
