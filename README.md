<p align="center">
  <img src="assets/red-widow.png" alt="Red Widow logo - VSIX and IDE extension security scanner" width="900">
</p>

<h1 align="center">Red Widow</h1>

<p align="center">
  <strong>VSIX, IDE extension, and AI developer workflow security scanner.</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="#license"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-black"></a>
  <a href="#what-it-checks"><img alt="VSIX scanner" src="https://img.shields.io/badge/VSIX-scanner-red"></a>
  <a href="#policy-format"><img alt="Policy as code" src="https://img.shields.io/badge/policy-as--code-blue"></a>
  <a href="#what-it-checks"><img alt="SARIF supported" src="https://img.shields.io/badge/SARIF-supported-brightgreen"></a>
  <a href="#contributing"><img alt="Contributions welcome" src="https://img.shields.io/badge/contributions-welcome-orange"></a>
</p>

`red-widow` is an open-source security scanner for VS Code-compatible IDE
extensions, VSIX packages, and developer workflow attack surfaces. It can inspect
`.vsix` packages, unpacked extension directories, locally installed extensions,
extension update diffs, lockfiles, policy files, inventory reports, and SARIF
output for CI.

Use Red Widow to find risky IDE extension behavior before it reaches developer
machines: bundled secrets, broad activation events, native binaries,
`child_process` usage, VS Code webview and terminal API abuse, environment
variable sweeping, executable download chains, sensitive local path access,
suspicious network domains, and dynamic canary exfiltration attempts.

The static scanner is intentionally dependency-free at runtime. Dynamic sandbox
runs require Node.js because Red Widow executes extension activation code through
an instrumented Node harness.

## Usage

For day-to-day repo checks, use the gate. It scans the current workspace's
`.vscode/extensions.json`, resolves recommended extensions from the VS Code
Marketplace or OpenVSX, caches downloaded VSIX packages under `.red-widow/`, and
scans any checked-in `.vsix` files it finds:

```bash
red-widow gate
red-widow approve
red-widow approve --reviewed-by security@example.com
red-widow gate --policy examples/policy.example.json
red-widow gate --json
```

The same gate also auto-detects VS Code-compatible AI-IDE workflow config in the
workspace, including `.vscode/mcp.json`, VS Code tasks/debug/settings,
Cursor/Windsurf MCP config, agent rules, `AGENTS.md`, Windsurf hooks, and
Windsurf ignore config. Harmless config discovery is reported as inventory;
concrete executable paths such as shell hooks, shell-wrapped MCP servers,
non-HTTPS remote MCP URLs, curl-to-shell tasks, or broad env-file exposure can
block.

Before push or in CI, make review items blocking:

```bash
red-widow gate --policy examples/policy.example.json --fail-on-review
```

Use the first-party GitHub Action in CI:

```yaml
- uses: red-widow/red-widow@v1
  with:
    workspace: .
    policy: examples/policy.example.json
    offline: "true"
    fail-on-review: "true"
    upload-sarif: "true"
```

Stay local-only when you do not want network access:

```bash
red-widow gate --offline
```

`red-widow approve` writes `red-widow.lock.json` for the resolved packages from
the current gate run. Future `red-widow gate` runs use that lockfile
automatically and flag version or package-hash drift.

Scan a specific VSIX or unpacked extension:

```bash
red-widow ./extension.vsix
red-widow ./unpacked-extension-directory
```

Compare an extension update:

```bash
red-widow --diff ./old.vsix ./new.vsix
```

Audit installed extensions:

```bash
red-widow --installed
red-widow --installed --format inventory
```

Audit the local machine's installed extensions plus global Cursor/Windsurf MCP
config:

```bash
red-widow gate --installed
red-widow inventory --format json
```

Export approved extensions into VS Code enterprise `extensions.allowed` policy:

```bash
red-widow export vscode-allowed --lockfile red-widow.lock.json --format settings-json
```

Run Red Widow inside VS Code with the editor extension in
[`vscode-extension/`](vscode-extension/). The extension runs the local CLI,
shows the gate decision in the status bar, and adds Problems diagnostics for
blocking and review findings. See [`docs/vscode-extension.md`](docs/vscode-extension.md).

Run a VSIX in a canary sandbox:

```bash
red-widow run ./extension.vsix --sandbox
```

Seed and check an AI coding-agent canary run:

```bash
red-widow agent seed /private/tmp/red-widow-agent-probe
red-widow agent show /private/tmp/red-widow-agent-probe
red-widow agent check ./agent-transcript.txt --workspace /private/tmp/red-widow-agent-probe
```

`agent seed` and `agent show` redact the canary marker by default so CI logs do
not accidentally expose it. Use `--reveal-marker` only for local manual probes.

Recommended extension IDs that cannot be resolved from an installed/local copy,
the lockfile, VS Code Marketplace, or OpenVSX produce `REVIEW` by default. Use
`--fail-on-review` when CI should block unresolved recommendations.

Useful advanced commands:

```bash
red-widow ./extension.vsix --format json
red-widow ./extension.vsix --fail-on high
red-widow ./extension.vsix --write-lockfile extensions.lock.json
red-widow ./extension.vsix --lockfile extensions.lock.json
red-widow approve --json
red-widow approve --lockfile red-widow.lock.json
red-widow inventory --format markdown
red-widow export vscode-allowed --format json
red-widow gate --workspace .
red-widow gate --offline
red-widow gate --installed --policy examples/policy.example.json
red-widow gate --installed --extension-root ./extensions
red-widow gate --recommendations .vscode/extensions.json
red-widow --installed --policy examples/policy.example.json
red-widow --installed --policy examples/policy.example.json --format sarif
red-widow --installed --format markdown
red-widow run ./extension.vsix --sandbox --keep-run
red-widow run ./extension.vsix --sandbox --format json
red-widow agent seed /private/tmp/red-widow-agent-probe --format json
red-widow agent show /private/tmp/red-widow-agent-probe --reveal-marker
red-widow agent check ./agent-transcript.txt --workspace /private/tmp/red-widow-agent-probe --format json
```

Create and use a baseline so CI reports only new risk:

```bash
red-widow --installed --policy examples/policy.example.json --write-baseline extensions.baseline.json
red-widow --installed --policy examples/policy.example.json --baseline extensions.baseline.json
```

When running from a checkout instead of an installed package, replace
`red-widow` with:

```bash
python3 -m red_widow
```

The dynamic sandbox creates a fake workspace with canary secrets, loads the
extension activation entry point through an instrumented Node harness, blocks
process and network calls, and reports proof when an extension reads canary
files, spawns a process, sends terminal commands, touches canary environment
values, creates unsafe webviews, or attempts to send canary material outbound.

Safety note: the dynamic runner is an instrumented canary harness, not an
operating-system or VM sandbox. Run unknown hostile packages inside an isolated
CI worker, container, or virtual machine.

For explicit target lists, use `--continue-on-error` to keep scanning after a
malformed package. Installed-extension scans continue by default and return
status 1 if any target could not be parsed.

Exit codes are stable for CI:

- `0`: scan passed, or findings are report-only under the selected options.
- `1`: scan/runtime error, malformed target, or dynamic harness error.
- `2`: policy violation, lockfile violation, `--fail-on` threshold, gate block, `--fail-on-review`, or dynamic block.

## Demo a Faulty VSIX

Build a deterministic intentionally faulty fixture:

```bash
python3 examples/build_faulty_vsix.py /private/tmp/red-widow-faulty.vsix
```

Run static and dynamic proof:

```bash
python3 -m red_widow /private/tmp/red-widow-faulty.vsix
python3 -m red_widow run /private/tmp/red-widow-faulty.vsix --sandbox
```

The generated fixture includes bundled secrets, a lifecycle script, a native
binary, child process usage, terminal command injection, env sweeping, webview
script/message behavior, a download-write-execute path, and canary exfiltration
code. It is meant for local demos and tests, not for publishing.

## What It Checks

| Area | What Red Widow Looks For |
| --- | --- |
| Manifest behavior | Activation events, broad `*` activation, workspace extension host usage, and package lifecycle scripts. |
| Secrets | Private keys, GitHub/OpenAI/AWS/Slack/npm tokens, and generic secret assignments. |
| Bundled credential files | Files such as `.env`, `.npmrc`, `.netrc`, `.git-credentials`, SSH keys, and cloud credential files. |
| Process execution | Node process execution APIs such as `child_process`, `exec`, `spawn`, `fork`, and sync variants. |
| Terminal APIs | `createTerminal().sendText(...)` paths that can inject commands into an integrated terminal. |
| Webviews | Script-enabled webviews, missing strict CSP, and `onDidReceiveMessage` handlers that need validation. |
| Environment access | Broad `process.env` enumeration or dynamic indexing that can sweep developer secrets. |
| Executable download chains | Runtime source files that combine network access, filesystem writes, and process execution. |
| Workspace trust | Risky runtime behavior without an apparent `vscode.workspace.isTrusted` gate, missing `capabilities.untrustedWorkspaces`, and unrestricted execution-sensitive settings. |
| VS Code MCP | `.vscode/mcp.json` local MCP stdio commands, remote MCP URLs, secret-like env usage, env files, and shell-wrapper command paths. |
| VS Code repo execution config | `.vscode/tasks.json`, `.vscode/launch.json`, and `.vscode/settings.json` commands, shell chains, env files, and sensitive file references. |
| Language model tools | VSIX `contributes.languageModelTools`, broad tool descriptions, and tool implementations that combine local data reads with network/process/terminal output. |
| Cursor/Windsurf MCP | Local MCP stdio commands, remote MCP URLs, secret-like env usage, env files, and shell-wrapper command paths. |
| AI agent rules | Risky instructions in `.cursor/rules`, `.cursorrules`, `AGENTS.md`, and Windsurf rules or workflows. |
| Windsurf hooks | Shell commands configured in `.windsurf/hooks.json`. |
| Windsurf ignore config | `.codeiumignore` patterns that re-include sensitive-looking files. |
| Local credential access | References to sensitive paths and variables such as `.ssh`, `.git-credentials`, `id_rsa`, cloud tokens, and credential environment variables. |
| Network endpoints | Runtime HTTP/HTTPS domains embedded in extension source files. |
| Native and script content | Native binaries such as `.node`, `.so`, `.dll`, `.dylib`, `.exe`, plus bundled shell scripts. |
| Obfuscation | Large minified JavaScript lines, `eval`, `atob`, `new Function`, `String.fromCharCode`, and large base64-like blobs. |
| Update diffs | Newly added findings, domains, native binaries, and activation-event changes between extension versions. |
| Dynamic sandbox proof | Canary file/env reads, terminal sendText calls, unsafe webview behavior, process-spawn attempts, outbound network access, and outbound canary exfiltration attempts. |
| AI coding-agent proof | Canary workspaces with untrusted prompt-injection content plus transcript/tool-trace checks for canary disclosure, sensitive file reads, unsafe commands, and outbound exfil paths. |
| Gate checks | Local VSIX packages, installed extensions, marketplace-resolved recommendations, and unresolved VS Code extension recommendations before they land in a repo or CI workflow. |

## Policy Format

Policy files are JSON and can allow or block extension IDs, publishers, domains,
and specific scanner rules.

```json
{
  "maxSeverity": "medium",
  "maxRiskScore": 9,
  "allowExtensions": ["esbenp.prettier-vscode", "github.*"],
  "blockExtensions": ["unknown.*"],
  "allowPublishers": ["GitHub", "ms-python"],
  "blockPublishers": ["suspicious-publisher"],
  "allowDomains": ["*.microsoft.com", "*.github.com"],
  "blockDomains": ["*.example"],
  "allowActivationStar": false,
  "allowNativeBinaries": false,
  "denyFindings": ["child-process-use", "private-key", "github-token"],
  "exceptions": [
    {
      "extension": "ms-python.*",
      "version": "2026.*",
      "ruleId": "native-binary",
      "scope": "dependency",
      "reason": "Approved bundled helper binaries."
    },
    {
      "extension": "github.*",
      "ruleId": "domain-blocked",
      "domain": "*.github.com",
      "reason": "Approved service domain."
    }
  ]
}
```

If a policy is passed and violations are found, `red-widow` exits with status 2.

Findings include metadata for triage:

- `confidence`: how reliable the signal is.
- `blocking`: whether the rule is strong enough to block by default.
- `scope`: `source`, `dependency`, `documentation`, `test`, `example`, `generated`, `manifest`, `config`, or `asset`.
- `remediation`: suggested review or cleanup action.

## Lockfile Format

```json
{
  "lockfileVersion": 2,
  "allowedExtensions": {
    "publisher.extension-name": {
      "version": "1.0.0",
      "sha256": "package-or-directory-digest",
      "source": "marketplace",
      "marketplaceSource": "openvsx",
      "sourceUrl": "https://open-vsx.org/api/publisher/extension-name/file/publisher.extension-name.vsix",
      "publisher": "publisher",
      "name": "extension-name",
      "approvedBy": "security@example.com",
      "reviewedBy": "security@example.com",
      "reviewedAt": "2026-05-06T00:00:00Z"
    }
  }
}
```

For directories, the digest is deterministic over relative file paths and file
contents. For `.vsix` files, the digest is the package SHA-256. Older lockfiles
with only `allowedExtensions` remain valid; Red Widow validates extension ID,
version, and package digest.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, test commands, and the current contribution priorities.

What Red Widow needs most right now:

| Need | Examples |
| --- | --- |
| Scanner fixtures | Safe intentionally risky VSIX samples for secrets, lifecycle scripts, native binaries, obfuscation, and network endpoints. |
| Detection coverage | More VSIX, extension manifest, MCP, CI workflow, and devcontainer risk checks. |
| False-positive reduction | Better scoping for generated files, dependencies, docs, tests, and examples. |
| Packaging and CI | Wheel/sdist smoke tests, GitHub Action examples, SARIF upload examples, and release automation. |
| Documentation | Real-world usage examples for policy, lockfiles, baselines, inventory, and update diffs. |

## License

MIT. See [LICENSE](LICENSE).
