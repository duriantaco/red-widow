from __future__ import annotations

from typing import Any


PRODUCT_INTENT = (
    "Red Widow answers one question: can this developer workflow change reach "
    "secrets, commands, or trusted tools before it reaches developers or CI?"
)
GATE_INTENT = (
    "Intent: gate IDE extension, MCP, and AI workflow changes before they reach "
    "developers or CI."
)
SCAN_INTENT = (
    "Intent: inspect one VSIX or extension directory for secrets, process or "
    "network access, and risky IDE APIs."
)
DIFF_INTENT = "Intent: show new extension risk introduced by an update."
DYNAMIC_INTENT = (
    "Intent: run extension activation in a canary workspace and block runtime "
    "behavior that crosses the sandbox boundary."
)
AGENT_PROBE_INTENT = (
    "Intent: create a canary workspace for checking whether an AI coding agent "
    "leaks files, markers, or tool boundaries."
)
AGENT_CHECK_INTENT = (
    "Intent: check an agent transcript or tool trace for canary leaks and unsafe "
    "tool-use evidence."
)
APPROVE_INTENT = "Intent: approve the exact extension packages that passed the gate."


def gate_next_action(report: Any) -> str:
    if getattr(report, "should_block", False):
        return "Fix or approve blocking items, then rerun the gate."
    if getattr(report, "scan_errors", None):
        return "Fix scan errors and rerun; use --strict in CI to block incomplete static coverage."
    if getattr(report, "has_review", False):
        return "Review unresolved or changed trust items; use --fail-on-review in CI when review must block."
    return "No action required; use approve to lock resolved extension packages when ready."


def scan_next_action(report: Any, decision: str) -> str:
    if decision == "BLOCK":
        return "Fix or approve blocking findings before this package is trusted."
    if getattr(report, "scan_warnings", None):
        return "Review scan warnings; use --strict in CI to block incomplete static coverage."
    if decision == "REVIEW":
        return "Review listed findings before approval."
    return "No action required for this package."


def diff_next_action(decision: str) -> str:
    if decision == "BLOCK":
        return "Reject or remediate this update before approval."
    if decision == "REVIEW":
        return "Review the changed behavior before approval."
    return "No action required for this update."


def dynamic_next_action(report: Any) -> str:
    if _has_blocking_harness_error(report):
        return "Fix dynamic harness errors, then rerun the sandbox."
    if getattr(report, "should_block", False):
        return "Fix blocking runtime behavior before approval."
    if getattr(report, "errors", None):
        return "Fix harness errors or rerun with --strict to block incomplete dynamic coverage."
    if getattr(report, "violations", None):
        return "Review runtime behavior before approval."
    return "No runtime action required."


def agent_check_next_action(report: Any) -> str:
    if getattr(report, "should_block", False):
        return "Fix the agent workflow or tool policy before using it with trusted workspaces."
    if getattr(report, "errors", None):
        return "Fix check errors, then rerun the agent check."
    if getattr(report, "violations", None):
        return "Review the flagged agent behavior before approval."
    return "No agent action required."


def _has_blocking_harness_error(report: Any) -> bool:
    if not getattr(report, "errors", None):
        return False
    return any(
        getattr(violation, "rule_id", "") == "harness-error" and getattr(violation, "blocking", False)
        for violation in getattr(report, "violations", ())
    )
