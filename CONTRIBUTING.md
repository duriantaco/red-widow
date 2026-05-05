# Contributing To Red Widow

Red Widow is focused on developer-workflow security: VSIX packages, IDE
extensions, MCP servers, coding agents, CI workflows, dev containers, and the
trust boundaries around local secrets and tooling.

The best contributions are small, test-backed improvements that make findings
more precise or make the CLI easier to run in CI.

## Development Setup

From the repository root:

```bash
python3 -m red_widow --help
pytest -q
python3 -m compileall -q red_widow tests
```

Dynamic harness tests require Node.js. They are skipped automatically when Node
is not available.

## Good First Contributions

Useful starter work:

| Area | Examples |
| --- | --- |
| Fixtures | Add safe generated VSIX fixtures for known risky patterns. |
| Tests | Add regression tests for malformed packages, edge-case manifests, and CLI output modes. |
| Docs | Improve examples for lockfiles, policies, baselines, SARIF, and CI usage. |
| Output | Make text, JSON, Markdown, and SARIF output clearer and more stable. |
| Rules | Add focused scanner rules with clear evidence and remediation text. |

## What We Need Most

High-impact contributions:

1. A fixture generator under `examples/fixtures/` for intentionally risky VSIX
   packages.
2. GitHub Actions examples for `red-widow` scans, update diffs, policy gates,
   and SARIF upload.
3. Better marketplace and source metadata for VS Code Marketplace, OpenVSX, and
   sideloaded VSIX packages.
4. More precise finding scopes for dependencies, generated files, test fixtures,
   examples, documentation, manifests, config, and runtime source.
5. Early MCP and AI-agent inventory support, aligned with the roadmap.

## Rule Contributions

When adding a scanner rule:

1. Add rule metadata in `red_widow/models.py`.
2. Include clear evidence that helps a reviewer confirm the behavior.
3. Set severity, confidence, blocking, scope, and remediation deliberately.
4. Add tests for true positives and at least one low-signal or false-positive
   case when possible.
5. Keep the rule deterministic and dependency-free unless there is a strong
   reason to change that.

## Testing Expectations

Run before submitting changes:

```bash
pytest -q
python3 -m compileall -q red_widow tests
```

For dynamic behavior, add a VSIX fixture in the test itself or through a fixture
builder. The test should prove the specific event or violation, such as canary
file reads, canary exfiltration, process spawning, or blocked network activity.

## Project Boundaries

Red Widow should not become a generic web application pentester or generic SAST
tool. Keep changes aligned with the product boundary:

- Static and dynamic security testing for IDE extensions.
- Developer workflow exploit-path proof.
- MCP, coding-agent, CI, and devcontainer trust boundaries.
- Policy, lockfile, inventory, and update-gating workflows.

## Pull Request Checklist

- The change is scoped to Red Widow's developer-workflow security lane.
- Tests cover the new behavior or bug fix.
- CLI output remains stable or the change is clearly intentional.
- New findings include useful evidence and remediation.
- Docs are updated when user-facing behavior changes.

