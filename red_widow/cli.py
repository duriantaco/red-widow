from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .agent import (
    AgentCheckReport,
    AgentViolation,
    check_agent_trace,
    create_agent_probe,
    load_agent_probe,
)
from .baseline import (
    apply_finding_baseline,
    filter_policy_violations,
    load_baseline,
    make_baseline,
)
from .dynamic.models import DynamicRunReport, DynamicViolation
from .dynamic.runner import DynamicRunOptions, run_extension
from .enterprise import vscode_allowed_extensions_policy
from .gate import GateItem, GateReport, run_gate
from .inventory import (
    inventory_report_markdown,
    inventory_report_text,
    make_inventory_report,
)
from .models import DiffReport, Finding, PolicyViolation, SCHEMA_VERSION, ScanReport, SEVERITY_ORDER
from .output import gate_markdown, gate_sarif_report, inventory_markdown, inventory_text, sarif_report
from .policy import evaluate_policy, load_policy
from .scanner import (
    diff_targets,
    discover_installed_extensions,
    make_lockfile,
    scan_target,
    validate_lockfile,
)


DEFAULT_LOCKFILE = "red-widow.lock.json"


class RedWidowHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=28, width=96)


@dataclass
class ScanCommandState:
    reports: list[ScanReport]
    scan_errors: list[dict[str, str]]
    lock_errors: list[str]
    policy_violations: list[PolicyViolation]
    suppressed_findings: int = 0
    suppressed_policy_violations: int = 0
    wrote_lockfile: str = ""
    wrote_baseline: str = ""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "run":
        return _run_dynamic_command(argv[1:])
    if argv and argv[0] == "gate":
        return _run_gate_command(argv[1:])
    if argv and argv[0] == "approve":
        return _run_approve_command(argv[1:])
    if argv and argv[0] == "agent":
        return _run_agent_command(argv[1:])
    if argv and argv[0] == "inventory":
        return _run_inventory_command(argv[1:])
    if argv and argv[0] == "export":
        return _run_export_command(argv[1:])

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _run_scan_command(parser, args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow: {exc}", file=sys.stderr)
        return 1


def _run_scan_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    output_format = "json" if args.json else args.format
    _validate_scan_args(parser, args, output_format)

    if args.diff:
        return _run_diff_command(args, output_format)

    targets, installed_targets, custom_roots = _collect_scan_targets(args)
    if not targets and not args.installed:
        parser.print_help(sys.stderr)
        return 2

    reports, scan_errors = _scan_command_targets(
        targets=targets,
        installed_targets=installed_targets,
        custom_roots=custom_roots,
        continue_on_error=args.continue_on_error or args.installed,
    )
    state = _build_scan_state(args, reports, scan_errors)
    _emit_scan_command_output(args, output_format, state)
    return _scan_command_exit(args, state)


def _validate_scan_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    output_format: str,
) -> None:
    if args.max_findings < 0:
        parser.error("--max-findings must be non-negative")
    if args.diff and (
        args.targets
        or args.installed
        or args.lockfile
        or args.write_lockfile
        or args.policy
        or args.baseline
        or args.write_baseline
    ):
        parser.error("--diff cannot be combined with targets, --installed, policy, or lockfile options")
    if args.diff and output_format not in {"text", "json"}:
        parser.error("--diff only supports --format text or --format json")


def _run_diff_command(args: argparse.Namespace, output_format: str) -> int:
    diff = diff_targets(args.diff[0], args.diff[1])
    if output_format == "json":
        print(json.dumps(diff.to_dict(), indent=2, sort_keys=True))
    else:
        _print_diff(diff, args.max_findings)
    return _exit_for_diff(diff, args.fail_on)


def _collect_scan_targets(args: argparse.Namespace) -> tuple[list[Path], list[Path], list[Path]]:
    targets = [Path(target) for target in args.targets]
    installed_targets: list[Path] = []
    custom_roots = [Path(root).expanduser() for root in args.extension_root]
    if args.installed:
        installed_targets = discover_installed_extensions(args.extension_root)
        targets.extend(installed_targets)
    return targets, installed_targets, custom_roots


def _scan_command_targets(
    targets: list[Path],
    installed_targets: list[Path],
    custom_roots: list[Path],
    *,
    continue_on_error: bool,
) -> tuple[list[ScanReport], list[dict[str, str]]]:
    reports: list[ScanReport] = []
    scan_errors: list[dict[str, str]] = []
    for target in targets:
        try:
            report = scan_target(target)
            _annotate_installed_report(report, installed_targets, custom_roots)
            reports.append(report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if not continue_on_error:
                raise
            scan_errors.append({"target": str(target), "error": str(exc)})
    return reports, scan_errors


def _build_scan_state(
    args: argparse.Namespace,
    reports: list[ScanReport],
    scan_errors: list[dict[str, str]],
) -> ScanCommandState:
    baseline = load_baseline(args.baseline) if args.baseline else {}
    policy = load_policy(args.policy) if args.policy else {}
    raw_policy_violations = evaluate_policy(reports, policy) if policy else []
    suppressed_findings = apply_finding_baseline(reports, baseline) if baseline else 0
    lock_errors = _scan_lock_errors(args.lockfile, reports)
    policy_violations = evaluate_policy(reports, policy) if policy else []
    suppressed_policy_violations = 0

    if baseline:
        policy_violations, suppressed_policy_violations = filter_policy_violations(
            policy_violations,
            baseline,
        )
        _, raw_suppressed = filter_policy_violations(raw_policy_violations, baseline)
        suppressed_policy_violations = max(suppressed_policy_violations, raw_suppressed)

    state = ScanCommandState(
        reports=reports,
        scan_errors=scan_errors,
        lock_errors=lock_errors,
        policy_violations=policy_violations,
        suppressed_findings=suppressed_findings,
        suppressed_policy_violations=suppressed_policy_violations,
    )
    _write_scan_artifacts(args, state)
    return state


def _scan_lock_errors(lockfile_path: str | None, reports: list[ScanReport]) -> list[str]:
    if not lockfile_path:
        return []
    with Path(lockfile_path).expanduser().open("r", encoding="utf-8") as fh:
        lockfile = json.load(fh)
    return validate_lockfile(reports, lockfile)


def _write_scan_artifacts(args: argparse.Namespace, state: ScanCommandState) -> None:
    if args.write_lockfile and (state.reports or not state.scan_errors):
        lockfile_path = Path(args.write_lockfile).expanduser()
        lockfile_path.write_text(
            json.dumps(make_lockfile(state.reports, reviewed_by=args.reviewed_by), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        state.wrote_lockfile = str(lockfile_path)
    if args.write_baseline and (state.reports or not state.scan_errors):
        baseline_path = Path(args.write_baseline).expanduser()
        baseline_path.write_text(
            json.dumps(make_baseline(state.reports, state.policy_violations), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        state.wrote_baseline = str(baseline_path)


def _emit_scan_command_output(
    args: argparse.Namespace,
    output_format: str,
    state: ScanCommandState,
) -> None:
    if output_format == "json":
        print(json.dumps(_scan_json_payload(state), indent=2, sort_keys=True))
    elif output_format == "sarif":
        print(json.dumps(sarif_report(state.reports, state.policy_violations), indent=2, sort_keys=True))
    elif output_format == "inventory":
        print(inventory_text(state.reports), end="")
        if state.scan_errors:
            _print_scan_errors(state.scan_errors)
    elif output_format == "markdown":
        print(inventory_markdown(state.reports), end="")
        if state.scan_errors:
            _print_scan_errors(state.scan_errors)
    else:
        _emit_scan_text_output(args, state)


def _scan_json_payload(state: ScanCommandState) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "reports": [report.to_dict() for report in state.reports],
        "inventory": [report.inventory_dict() for report in state.reports],
        "lockfileErrors": state.lock_errors,
        "scanErrors": state.scan_errors,
        "policyViolations": [violation.to_dict() for violation in state.policy_violations],
        "baseline": {
            "suppressedFindings": state.suppressed_findings,
            "suppressedPolicyViolations": state.suppressed_policy_violations,
            "wroteBaseline": state.wrote_baseline,
        },
        "wroteLockfile": state.wrote_lockfile,
    }


def _emit_scan_text_output(args: argparse.Namespace, state: ScanCommandState) -> None:
    for index, report in enumerate(state.reports):
        if index:
            print()
        _print_report(report, args.max_findings)
    if state.wrote_lockfile:
        print(f"\nWrote lockfile: {state.wrote_lockfile}")
    if state.wrote_baseline:
        print(f"\nWrote baseline: {state.wrote_baseline}")
    if state.suppressed_findings or state.suppressed_policy_violations:
        print(
            "\nBaseline suppressed: "
            f"{state.suppressed_findings} finding(s), "
            f"{state.suppressed_policy_violations} policy violation(s)"
        )
    if state.lock_errors:
        print("\nLockfile errors:")
        for error in state.lock_errors:
            print(f"  - {error}")
    if state.policy_violations:
        _print_policy_violations(state.policy_violations)
    if state.scan_errors:
        _print_scan_errors(state.scan_errors)


def _scan_command_exit(args: argparse.Namespace, state: ScanCommandState) -> int:
    if state.lock_errors or state.policy_violations:
        return 2
    if state.scan_errors:
        return 1
    return _exit_for_reports(state.reports, args.fail_on)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow",
        formatter_class=RedWidowHelpFormatter,
        description="""Red Widow scans IDE extensions and AI developer workflow risk.

Common commands:
  red-widow gate           Gate current repo before merge or CI
  red-widow inventory      Collect extension, MCP, and agent-workflow inventory
  red-widow run            Run a VSIX in a canary sandbox
  red-widow approve        Write red-widow.lock.json approvals
  red-widow agent          Seed or check coding-agent canary probes
  red-widow export         Export enterprise policy

Examples:
  red-widow gate --offline
  red-widow ./extension.vsix
  red-widow inventory --format json
""",
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="VSIX files or extension dirs")
    parser.add_argument("--installed", action="store_true", help="scan locally installed VS Code-compatible extensions")
    parser.add_argument(
        "--extension-root",
        action="append",
        default=[],
        metavar="DIR",
        help="extra installed-extension root",
    )
    parser.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="diff two extension packages or dirs")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument(
        "--format",
        choices=["text", "json", "inventory", "markdown", "sarif"],
        metavar="FORMAT",
        default="text",
        help="text, json, inventory, markdown, or sarif",
    )
    parser.add_argument("--lockfile", metavar="FILE", help="validate against a lockfile")
    parser.add_argument("--write-lockfile", metavar="FILE", help="write a lockfile")
    parser.add_argument("--reviewed-by", metavar="NAME", default="", help="reviewer for written lockfiles")
    parser.add_argument("--policy", metavar="FILE", help="enforce policy JSON")
    parser.add_argument("--baseline", metavar="FILE", help="suppress baseline findings")
    parser.add_argument("--write-baseline", metavar="FILE", help="write a baseline")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="continue after malformed targets",
    )
    parser.add_argument(
        "--fail-on",
        metavar="LEVEL",
        choices=["low", "medium", "high", "critical"],
        help="fail on severity: low, medium, high, critical",
    )
    parser.add_argument("--max-findings", metavar="N", type=int, default=50, help="max findings to print")
    return parser


def _run_dynamic_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="red-widow run",
        formatter_class=RedWidowHelpFormatter,
        description="Run a VS Code-compatible extension in a Red Widow canary sandbox.",
    )
    parser.add_argument("target", metavar="TARGET", help="VSIX file or extension dir")
    parser.add_argument(
        "--sandbox",
        action="store_true",
        default=True,
        help="run in a canary sandbox; this is the only supported mode",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        metavar="FORMAT",
        default="text",
        help="text or json",
    )
    parser.add_argument("--timeout", metavar="SEC", type=int, default=10, help="harness timeout")
    parser.add_argument(
        "--keep-run",
        action="store_true",
        help="preserve the run directory under .red-widow/runs for replay inspection",
    )
    parser.add_argument("--run-root", metavar="DIR", help="directory for preserved run artifacts")
    parser.add_argument("--node", metavar="EXE", default="node", help="Node executable")
    args = parser.parse_args(argv)

    try:
        report = run_extension(
            args.target,
            DynamicRunOptions(
                timeout=args.timeout,
                keep_run=args.keep_run,
                run_root=Path(args.run_root).expanduser() if args.run_root else None,
                node=args.node,
            ),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow run: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_dynamic_report(report, keep_run=args.keep_run)

    if report.should_block:
        return 2
    if report.errors:
        return 1
    return 0


def _run_agent_command(argv: list[str]) -> int:
    parser = _build_agent_command_parser()
    args = parser.parse_args(argv)
    output_format = "json" if getattr(args, "json", False) else args.format

    try:
        if args.agent_command == "seed":
            probe = create_agent_probe(args.workspace)
            payload = probe.to_dict(redact_marker=not args.reveal_marker)
            if output_format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                _print_agent_probe(payload)
            return 0
        if args.agent_command == "check":
            report = check_agent_trace(
                args.trace,
                marker=args.marker or "",
                workspace=Path(args.workspace).expanduser() if args.workspace else None,
            )
            if output_format == "json":
                print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
            else:
                _print_agent_check_report(report)
            return _agent_check_exit(report)
        if args.agent_command == "show":
            probe = load_agent_probe(args.workspace)
            payload = probe.to_dict(redact_marker=not args.reveal_marker)
            if output_format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                _print_agent_probe(payload)
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow agent: {exc}", file=sys.stderr)
        return 1

    parser.print_help(sys.stderr)
    return 2


def _build_agent_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow agent",
        formatter_class=RedWidowHelpFormatter,
        description="Seed and check AI coding-agent canary probes.",
    )
    subparsers = parser.add_subparsers(dest="agent_command", required=True)

    seed = subparsers.add_parser(
        "seed",
        formatter_class=RedWidowHelpFormatter,
        help="create a canary workspace for an AI coding agent run",
    )
    seed.add_argument("workspace", metavar="DIR", help="empty workspace dir")
    seed.add_argument(
        "--reveal-marker",
        action="store_true",
        help="print the raw canary marker; default output redacts it",
    )
    seed.add_argument("--json", action="store_true", help="alias for --format json")
    seed.add_argument("--format", choices=["text", "json"], metavar="FORMAT", default="text", help="text or json")

    check = subparsers.add_parser(
        "check",
        formatter_class=RedWidowHelpFormatter,
        help="check an agent transcript or tool trace for canary leaks",
    )
    check.add_argument("trace", metavar="TRACE", help="transcript, command log, or JSONL trace")
    check.add_argument(
        "--workspace",
        metavar="DIR",
        help="agent probe workspace; defaults to marker-only checks unless provided",
    )
    check.add_argument("--marker", metavar="VALUE", help="explicit canary marker")
    check.add_argument("--json", action="store_true", help="alias for --format json")
    check.add_argument("--format", choices=["text", "json"], metavar="FORMAT", default="text", help="text or json")

    show = subparsers.add_parser(
        "show",
        formatter_class=RedWidowHelpFormatter,
        help="print the saved probe task and metadata",
    )
    show.add_argument("workspace", metavar="DIR", help="agent probe workspace")
    show.add_argument(
        "--reveal-marker",
        action="store_true",
        help="print the raw canary marker; default output redacts it",
    )
    show.add_argument("--json", action="store_true", help="alias for --format json")
    show.add_argument("--format", choices=["text", "json"], metavar="FORMAT", default="text", help="text or json")
    return parser


def _run_inventory_command(argv: list[str]) -> int:
    parser = _build_inventory_command_parser()
    args = parser.parse_args(argv)
    output_format = "json" if args.json else args.format

    try:
        gate = run_gate(
            targets=args.targets,
            workspaces=args.workspace or [Path.cwd()],
            recommendation_paths=args.recommendations,
            installed=not args.no_installed,
            extension_roots=args.extension_root,
            policy=load_policy(args.policy) if args.policy else {},
            lockfile=_load_gate_lockfile(_defaulted_lockfile_path(args.lockfile)),
            offline=not args.online,
        )
        report = make_inventory_report(gate)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow inventory: {exc}", file=sys.stderr)
        return 1

    if output_format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    elif output_format == "markdown":
        print(inventory_report_markdown(report), end="")
    else:
        print(inventory_report_text(report), end="")
    return 1 if report.gate.scan_errors else 0


def _build_inventory_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow inventory",
        formatter_class=RedWidowHelpFormatter,
        description="Collect IDE extension, MCP, and AI developer workflow inventory for a machine or workspace.",
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="VSIX files or extension dirs")
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        metavar="DIR",
        help="workspace dir",
    )
    parser.add_argument(
        "--recommendations",
        action="append",
        default=[],
        metavar="FILE",
        help="VS Code extensions.json file",
    )
    parser.add_argument(
        "--no-installed",
        action="store_true",
        help="skip installed extensions and global AI IDE config",
    )
    parser.add_argument(
        "--extension-root",
        action="append",
        default=[],
        metavar="DIR",
        help="extra installed-extension root",
    )
    parser.add_argument("--policy", metavar="FILE", help="evaluate policy JSON")
    parser.add_argument(
        "--lockfile",
        metavar="FILE",
        help=f"validate lockfile; defaults to {DEFAULT_LOCKFILE} when present",
    )
    parser.add_argument("--online", action="store_true", help="resolve recommended extensions from marketplaces")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        metavar="FORMAT",
        default="text",
        help="text, json, or markdown",
    )
    return parser


def _run_gate_command(argv: list[str]) -> int:
    parser = _build_gate_command_parser()
    args = parser.parse_args(argv)
    output_format = "json" if args.json else args.format

    try:
        report = _gate_report_from_args(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow gate: {exc}", file=sys.stderr)
        return 1

    _emit_gate_command_output(report, output_format)
    return _gate_command_exit(report, fail_on_review=args.fail_on_review)


def _build_gate_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow gate",
        formatter_class=RedWidowHelpFormatter,
        description="Gate IDE extension trust changes for pre-commit, pre-push, and CI.",
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="VSIX files or extension dirs")
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        metavar="DIR",
        help="workspace dir",
    )
    parser.add_argument(
        "--recommendations",
        action="append",
        default=[],
        metavar="FILE",
        help="VS Code extensions.json file",
    )
    parser.add_argument("--installed", action="store_true", help="gate locally installed VS Code-compatible extensions")
    parser.add_argument(
        "--extension-root",
        action="append",
        default=[],
        metavar="DIR",
        help="extra installed-extension root",
    )
    parser.add_argument("--policy", metavar="FILE", help="enforce policy JSON")
    parser.add_argument(
        "--lockfile",
        metavar="FILE",
        help=f"validate lockfile; defaults to {DEFAULT_LOCKFILE} when present",
    )
    parser.add_argument("--offline", action="store_true", help="do not resolve recommended extensions from marketplaces")
    parser.add_argument("--fail-on-review", action="store_true", help="exit with code 2 when the gate decision is REVIEW")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown", "sarif"],
        metavar="FORMAT",
        default="text",
        help="text, json, markdown, or sarif",
    )
    return parser


def _gate_report_from_args(args: argparse.Namespace) -> GateReport:
    policy = load_policy(args.policy) if args.policy else {}
    return run_gate(
        targets=args.targets,
        workspaces=args.workspace,
        recommendation_paths=args.recommendations,
        installed=args.installed,
        extension_roots=args.extension_root,
        policy=policy,
        lockfile=_load_gate_lockfile(_defaulted_lockfile_path(args.lockfile)),
        offline=args.offline,
    )


def _load_gate_lockfile(lockfile_path: Path | None) -> dict[str, Any]:
    if not lockfile_path:
        return {}
    with lockfile_path.open("r", encoding="utf-8") as fh:
        lockfile = json.load(fh)
    if not isinstance(lockfile, dict):
        raise ValueError("lockfile must contain a JSON object")
    return lockfile


def _emit_gate_command_output(report: GateReport, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    elif output_format == "markdown":
        print(gate_markdown(report), end="")
    elif output_format == "sarif":
        print(json.dumps(gate_sarif_report(report), indent=2, sort_keys=True))
    else:
        _print_gate_report(report)


def _gate_command_exit(report: GateReport, *, fail_on_review: bool) -> int:
    if report.should_block:
        return 2
    if report.scan_errors:
        return 1
    if fail_on_review and report.has_review:
        return 2
    return 0


def _run_approve_command(argv: list[str]) -> int:
    parser = _build_approve_command_parser()
    args = parser.parse_args(argv)
    output_format = "json" if args.json else args.format

    try:
        report = _approve_report_from_args(args)
        lockfile_path = Path(args.lockfile).expanduser()
        wrote_lockfile = _write_approval_lockfile(report, lockfile_path, reviewed_by=args.reviewed_by)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow approve: {exc}", file=sys.stderr)
        return 1

    _emit_approve_command_output(report, lockfile_path, output_format, wrote_lockfile=wrote_lockfile)
    return _approve_command_exit(report)


def _build_approve_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow approve",
        formatter_class=RedWidowHelpFormatter,
        description="Approve the current workspace's resolved IDE extensions into a Red Widow lockfile.",
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="VSIX files or extension dirs")
    parser.add_argument(
        "--workspace",
        action="append",
        default=[],
        metavar="DIR",
        help="workspace dir",
    )
    parser.add_argument(
        "--recommendations",
        action="append",
        default=[],
        metavar="FILE",
        help="VS Code extensions.json file",
    )
    parser.add_argument("--installed", action="store_true", help="include locally installed VS Code-compatible extensions")
    parser.add_argument(
        "--extension-root",
        action="append",
        default=[],
        metavar="DIR",
        help="extra installed-extension root",
    )
    parser.add_argument("--policy", metavar="FILE", help="apply policy before approval")
    parser.add_argument("--reviewed-by", metavar="NAME", default="", help="reviewer for lockfile")
    parser.add_argument(
        "--lockfile",
        metavar="FILE",
        default=DEFAULT_LOCKFILE,
        help=f"lockfile to write; defaults to {DEFAULT_LOCKFILE}",
    )
    parser.add_argument("--offline", action="store_true", help="do not resolve recommended extensions from marketplaces")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        metavar="FORMAT",
        default="text",
        help="text or json",
    )
    return parser


def _approve_report_from_args(args: argparse.Namespace) -> GateReport:
    policy = load_policy(args.policy) if args.policy else {}
    return run_gate(
        targets=args.targets,
        workspaces=args.workspace,
        recommendation_paths=args.recommendations,
        installed=args.installed,
        extension_roots=args.extension_root,
        policy=policy,
        lockfile={},
        offline=args.offline,
    )


def _write_approval_lockfile(report: GateReport, lockfile_path: Path, *, reviewed_by: str = "") -> bool:
    if report.should_block or report.scan_errors:
        return False
    lockfile = make_lockfile(
        report.reports,
        reviewed_by=reviewed_by,
        source_urls=_marketplace_source_urls(report),
    )
    lockfile_path.write_text(
        json.dumps(lockfile, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return True


def _marketplace_source_urls(report: GateReport) -> dict[str, str]:
    return {package.extension_id: package.download_url for package in report.marketplace_packages}


def _emit_approve_command_output(
    report: GateReport,
    lockfile_path: Path,
    output_format: str,
    *,
    wrote_lockfile: bool,
) -> None:
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "wroteLockfile": str(lockfile_path) if wrote_lockfile else "",
        "approvedExtensions": len(report.reports) if wrote_lockfile else 0,
        "gate": report.to_dict(),
    }
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Red Widow approve")
        print(f"Gate decision: {report.decision}")
        if wrote_lockfile:
            print(f"Wrote lockfile: {lockfile_path}")
            print(f"Approved extensions: {len(report.reports)}")
        else:
            print("Wrote lockfile: no")
        if report.has_review:
            print("Review items remain; lockfile only approves resolved scanned packages.")


def _approve_command_exit(report: GateReport) -> int:
    if report.should_block:
        return 2
    if report.scan_errors:
        return 1
    return 0


def _run_export_command(argv: list[str]) -> int:
    parser = _build_export_command_parser()
    args = parser.parse_args(argv)

    try:
        if args.export_command == "vscode-allowed":
            lockfile = _load_gate_lockfile(Path(args.lockfile).expanduser())
            payload = vscode_allowed_extensions_policy(
                lockfile,
                block_unlisted=not args.allow_unlisted,
                pin_versions=not args.no_pin_versions,
            )
            output = payload["settings"] if args.format == "settings-json" else payload
            text = json.dumps(output, indent=2, sort_keys=True) + "\n"
            if args.output:
                Path(args.output).expanduser().write_text(text, encoding="utf-8")
            else:
                print(text, end="")
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"red-widow export: {exc}", file=sys.stderr)
        return 1

    parser.print_help(sys.stderr)
    return 2


def _build_export_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red-widow export",
        formatter_class=RedWidowHelpFormatter,
        description="Export Red Widow approvals into enterprise policy formats.",
    )
    subparsers = parser.add_subparsers(dest="export_command", required=True)

    vscode = subparsers.add_parser(
        "vscode-allowed",
        formatter_class=RedWidowHelpFormatter,
        help="export a VS Code extensions.allowed policy from a Red Widow lockfile",
    )
    vscode.add_argument(
        "--lockfile",
        metavar="FILE",
        default=DEFAULT_LOCKFILE,
        help=f"lockfile to export; defaults to {DEFAULT_LOCKFILE}",
    )
    vscode.add_argument(
        "--allow-unlisted",
        action="store_true",
        help="do not add an explicit '*' block entry for unapproved extensions",
    )
    vscode.add_argument(
        "--no-pin-versions",
        action="store_true",
        help="allow approved extension IDs without pinning to lockfile versions",
    )
    vscode.add_argument(
        "--format",
        choices=["json", "settings-json"],
        metavar="FORMAT",
        default="json",
        help="json or settings-json",
    )
    vscode.add_argument("--output", metavar="FILE", help="write output to file")
    return parser


def _defaulted_lockfile_path(path: str | None) -> Path | None:
    if path:
        return Path(path).expanduser()
    candidate = Path(DEFAULT_LOCKFILE)
    if candidate.is_file():
        return candidate
    return None


def _print_gate_report(report: GateReport) -> None:
    summary = report.summary
    print("Red Widow gate")
    print(f"Decision: {report.decision} - {report.reason}")
    print(
        "Summary: "
        f"{summary['scannedPackages']} scanned package(s), "
        f"{summary['recommendations']} recommendation(s), "
        f"{summary['marketplacePackages']} marketplace package(s), "
        f"{summary.get('infoItems', 0)} info item(s), "
        f"{summary['blockingItems']} blocking item(s), "
        f"{summary['reviewItems']} review item(s), "
        f"{summary['scanErrors']} scan error(s)"
    )

    blocking_findings = [
        (report_item, finding)
        for report_item in report.reports
        for finding in report_item.findings
        if finding.blocking
    ]
    review_findings = [
        (report_item, finding)
        for report_item in report.reports
        for finding in report_item.findings
        if not finding.blocking
    ]

    if report.blocking_items or report.policy_violations or report.lockfile_errors or blocking_findings:
        print("\nBlocking items:")
        for item in report.blocking_items:
            _print_gate_item(item)
        for violation in report.policy_violations:
            detail = f" - {violation.detail}" if violation.detail else ""
            print(f"  [{violation.severity.upper()}] {violation.rule_id}: {violation.message}{detail}")
        for error in report.lockfile_errors:
            print(f"  [HIGH] lockfile: {error}")
        for scan_report, finding in blocking_findings:
            _print_gate_finding(scan_report, finding)

    if report.info_items:
        print("\nAI IDE workflow items:")
        for item in report.info_items:
            _print_gate_item(item)

    if report.review_items or review_findings:
        print("\nReview items:")
        for item in report.review_items:
            _print_gate_item(item)
        for scan_report, finding in review_findings:
            _print_gate_finding(scan_report, finding)

    if report.scan_errors:
        _print_scan_errors(report.scan_errors)


def _print_gate_item(item: GateItem) -> None:
    detail = f" - {item.detail}" if item.detail else ""
    target = f" ({item.target})" if item.target else ""
    print(f"  [{item.severity.upper()}] {item.rule_id}: {item.message}{target}{detail}")


def _print_gate_finding(scan_report: ScanReport, finding: Finding) -> None:
    detail = f" - {finding.detail}" if finding.detail else ""
    path = f" {finding.path}" if finding.path else ""
    print(
        f"  [{finding.severity.upper()}] {finding.rule_id}: "
        f"{scan_report.extension_id}{path}{detail}"
    )


def _print_dynamic_report(report: DynamicRunReport, *, keep_run: bool = False) -> None:
    extension_label = report.scan.extension_id
    if report.scan.version:
        extension_label += f" {report.scan.version}"
    decision, reason = _dynamic_decision(report)
    blocking_count = sum(1 for violation in report.violations if violation.blocking)

    print("Red Widow dynamic sandbox")
    print(f"Decision: {decision} - {reason}")
    print(f"Extension: {extension_label}")
    print(f"Target: {report.target}")
    if keep_run:
        print(f"Sandbox workspace: {report.workspace_dir}")
        print(f"Run artifacts: {report.run_dir}")
    else:
        print("Sandbox workspace: temporary canary workspace (discarded)")
        print("Run artifacts: discarded (use --keep-run to preserve)")
    print(
        "Summary: "
        f"{len(report.violations)} violation(s), "
        f"{blocking_count} blocking, "
        f"{len(report.events)} event(s), "
        f"{len(report.errors)} error(s)"
    )

    if report.violations:
        blocking = [violation for violation in report.violations if violation.blocking]
        review = [violation for violation in report.violations if not violation.blocking]
        if blocking:
            print("\nBlocking violations:")
            _print_dynamic_violations(blocking)
        if review:
            print("\nReview violations:")
            _print_dynamic_violations(review)
    else:
        print("\nDynamic violations: none")

    if report.errors:
        print("\nRun errors:")
        for error in report.errors:
            print(f"  - {error}")


def _print_dynamic_violations(violations: list[DynamicViolation]) -> None:
    for violation in violations:
        detail = f" - {violation.detail}" if violation.detail else ""
        print(f"  [{violation.severity.upper()}] {violation.rule_id}: {violation.title}{detail}")
        for evidence in violation.evidence:
            print(f"    evidence: {evidence}")


def _print_agent_probe(probe: dict[str, Any]) -> None:
    print("Red Widow agent probe")
    print(f"Workspace: {probe.get('workspaceDir', '')}")
    print(f"Canary marker: {probe.get('canaryMarker', '')}")
    print("\nSuggested task:")
    print(str(probe.get("task", "")))
    files = probe.get("files", {})
    if isinstance(files, dict):
        print(f"\nFiles: {len(files)}")
        for relative_path in sorted(files)[:10]:
            print(f"  - {relative_path}: {files[relative_path]}")


def _print_agent_check_report(report: AgentCheckReport) -> None:
    decision, reason = _agent_decision(report)
    blocking_count = sum(1 for violation in report.violations if violation.blocking)

    print("Red Widow agent check")
    print(f"Decision: {decision} - {reason}")
    print(f"Trace: {report.trace}")
    if report.workspace_dir:
        print(f"Workspace: {report.workspace_dir}")
    print(
        "Summary: "
        f"{len(report.violations)} violation(s), "
        f"{blocking_count} blocking, "
        f"{len(report.errors)} error(s)"
    )

    if report.violations:
        blocking = [violation for violation in report.violations if violation.blocking]
        review = [violation for violation in report.violations if not violation.blocking]
        if blocking:
            print("\nBlocking violations:")
            _print_agent_violations(blocking)
        if review:
            print("\nReview violations:")
            _print_agent_violations(review)
    else:
        print("\nAgent violations: none")

    if report.errors:
        print("\nCheck errors:")
        for error in report.errors:
            print(f"  - {error}")


def _print_agent_violations(violations: list[AgentViolation]) -> None:
    for violation in violations:
        detail = f" - {violation.detail}" if violation.detail else ""
        print(f"  [{violation.severity.upper()}] {violation.rule_id}: {violation.title}{detail}")
        for evidence in violation.evidence:
            print(f"    evidence: {evidence}")


def _agent_decision(report: AgentCheckReport) -> tuple[str, str]:
    if report.should_block:
        return "BLOCK", "agent trace crossed a canary or tool-use boundary"
    if report.violations:
        return "REVIEW", "agent trace contains reviewable risk indicators"
    if report.errors:
        return "REVIEW", "agent check completed with reduced coverage"
    return "PASS", "no agent canary or unsafe tool-use evidence found"


def _agent_check_exit(report: AgentCheckReport) -> int:
    if report.should_block:
        return 2
    if report.errors:
        return 1
    return 0


def _dynamic_decision(report: DynamicRunReport) -> tuple[str, str]:
    if report.should_block:
        return "BLOCK", "blocking runtime violation observed"
    if report.violations:
        return "REVIEW", "runtime activity needs review"
    if report.errors:
        return "REVIEW", "harness completed with errors"
    return "PASS", "no dynamic violations observed"


def _print_report(report: ScanReport, max_findings: int) -> None:
    extension_label = report.extension_id
    if report.version:
        extension_label += f" {report.version}"
    decision, reason = _scan_decision(report)
    severity_counts = _severity_counts(report.findings)
    blocking_findings = [finding for finding in report.findings if finding.blocking]
    review_findings = [finding for finding in report.findings if not finding.blocking]

    print("Red Widow scan")
    print(f"Decision: {decision} - {reason}")
    print(f"Extension: {extension_label}")
    print(f"Target: {report.target}")
    if report.editor or report.install_source:
        source = ", ".join(part for part in (report.editor, report.install_source) if part)
        print(f"Source: {source}")
    print(
        "Risk: "
        f"{report.risk_label} (score {report.risk_score}, highest {report.highest_severity.upper()})"
    )
    print(
        "Findings: "
        f"{len(report.findings)} total, "
        f"{len(blocking_findings)} blocking "
        f"({_format_severity_counts(severity_counts)})"
    )
    print(f"Package: {report.file_count} file(s), {_format_bytes(report.total_size)}, sha256 {report.package_sha256}")
    if report.activation_events:
        print(f"Activation: {', '.join(report.activation_events)}")
    if report.domains or report.native_binaries:
        indicators: list[str] = []
        if report.domains:
            indicators.append(f"{len(report.domains)} domain(s): {', '.join(report.domains[:8])}")
        if report.native_binaries:
            indicators.append(
                f"{len(report.native_binaries)} native binary/binaries: "
                f"{', '.join(report.native_binaries[:8])}"
            )
        print(f"Indicators: {'; '.join(indicators)}")

    if not report.findings:
        print("\nFindings: none")
        return

    printed = 0
    if blocking_findings:
        print("\nBlocking findings:")
        printed += _print_findings(blocking_findings, max_findings - printed)
    if review_findings and printed < max_findings:
        print("\nReview findings:")
        printed += _print_findings(review_findings, max_findings - printed)
    remaining = len(report.findings) - printed
    if remaining > 0:
        print(f"  ... {remaining} more finding(s)")


def _print_findings(findings: list[Finding], limit: int) -> int:
    if limit <= 0:
        return 0
    printed = 0
    for finding in findings[:limit]:
        detail = f" - {finding.detail}" if finding.detail else ""
        path = f" ({finding.path})" if finding.path else ""
        scope = f", scope {finding.scope}" if finding.scope else ""
        print(f"  [{finding.severity.upper()}] {finding.rule_id}: {finding.title}{path}{detail}")
        print(
            f"    confidence {finding.confidence}, "
            f"{'blocking' if finding.blocking else 'review'}{scope}"
        )
        if finding.remediation:
            print(f"    fix: {finding.remediation}")
        for evidence in finding.evidence:
            print(f"    evidence: {evidence}")
        printed += 1
    return printed


def _scan_decision(report: ScanReport) -> tuple[str, str]:
    if any(finding.blocking for finding in report.findings):
        return "BLOCK", "blocking findings require review before approval"
    if report.findings:
        return "REVIEW", "non-blocking risk indicators found"
    return "PASS", "no findings detected"


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _format_severity_counts(counts: dict[str, int]) -> str:
    parts = [
        f"{name} {counts.get(name, 0)}"
        for name in ("critical", "high", "medium", "low")
        if counts.get(name, 0)
    ]
    return ", ".join(parts) if parts else "none"


def _print_diff(diff: DiffReport, max_findings: int) -> None:
    decision, reason = _diff_decision(diff)
    blocking_findings = [finding for finding in diff.added_findings if finding.blocking]
    review_findings = [finding for finding in diff.added_findings if not finding.blocking]

    print("Red Widow update diff")
    print(f"Decision: {decision} - {reason}")
    print(
        "Extension: "
        f"{diff.new.extension_id} {diff.old.version or '<unknown>'} -> {diff.new.version or '<unknown>'}"
    )
    print(f"Old target: {diff.old.target}")
    print(f"New target: {diff.new.target}")
    print(f"New risk: {diff.new.risk_label} (score {diff.new.risk_score})")
    print(
        "Changes: "
        f"{len(diff.added_findings)} new finding(s), "
        f"{len(blocking_findings)} blocking, "
        f"{len(diff.added_domains)} new domain(s), "
        f"{len(diff.added_native_binaries)} new native binary/binaries"
    )

    if diff.activation_changed:
        print(
            "Activation changed: "
            f"{_join_or_none(diff.old.activation_events)} -> {_join_or_none(diff.new.activation_events)}"
        )
    if diff.added_domains:
        print(f"New domains: {', '.join(diff.added_domains)}")
    if diff.added_native_binaries:
        print(f"New native binaries: {', '.join(diff.added_native_binaries)}")

    if not diff.added_findings:
        print("\nNew findings: none")
        return

    printed = 0
    if blocking_findings:
        print("\nNew blocking findings:")
        printed += _print_findings(blocking_findings, max_findings - printed)
    if review_findings and printed < max_findings:
        print("\nNew review findings:")
        printed += _print_findings(review_findings, max_findings - printed)
    remaining = len(diff.added_findings) - printed
    if remaining > 0:
        print(f"  ... {remaining} more new finding(s)")


def _diff_decision(diff: DiffReport) -> tuple[str, str]:
    if any(finding.blocking for finding in diff.added_findings):
        return "BLOCK", "update adds blocking findings"
    if diff.added_findings or diff.added_domains or diff.added_native_binaries or diff.activation_changed:
        return "REVIEW", "update changes security-relevant behavior"
    return "PASS", "no new security-relevant changes detected"


def _print_policy_violations(violations: list[PolicyViolation]) -> None:
    print("\nPolicy violations:")
    for violation in violations:
        detail = f" - {violation.detail}" if violation.detail else ""
        print(f"  [{violation.severity.upper()}] {violation.message}{detail}")


def _print_scan_errors(errors: list[dict[str, str]]) -> None:
    print("\nScan errors:")
    for error in errors:
        print(f"  - {error['target']}: {error['error']}")


def _annotate_installed_report(
    report: ScanReport, installed_targets: list[Path], custom_roots: list[Path]
) -> None:
    if not installed_targets:
        return
    target = _safe_resolve(Path(report.target))
    installed = {_safe_resolve(path) for path in installed_targets}
    if target not in installed:
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


def _exit_for_reports(reports: Iterable[ScanReport], threshold: str | None) -> int:
    if not threshold:
        return 0
    threshold_value = SEVERITY_ORDER[threshold]
    for report in reports:
        if SEVERITY_ORDER.get(report.highest_severity, 0) >= threshold_value:
            return 2
    return 0


def _exit_for_diff(diff: DiffReport, threshold: str | None) -> int:
    if not threshold:
        return 0
    threshold_value = SEVERITY_ORDER[threshold]
    for finding in diff.added_findings:
        if SEVERITY_ORDER.get(finding.severity, 0) >= threshold_value:
            return 2
    return 0


def _format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _join_or_none(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "<none>"
