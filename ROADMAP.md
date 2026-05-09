# Red Widow Roadmap

Red Widow should grow from an open-source IDE-extension scanner into a dynamic
security tester for developer workflows. The wedge is not generic SAST, a web
app pentester, or an AI coding assistant. The wedge is pre-production
supply-chain security: IDE extensions, MCP servers, coding agents, CI workflows,
dev containers, staging trust boundaries, update diffs, lockfiles, policy, and
eventually enforcement.

## North Star

Prove exploit paths across IDE, AI agent, CI, and staging workflows before they
can reach production.

The central question:

> Can an attacker reach production, secrets, source code, or trusted tools by
> abusing the developer workflow?

Good positioning:

- Dependabot for IDE extensions.
- Dynamic security testing for AI developer workflows.
- An extension and agent firewall for developer machines.
- SBOM plus EDR for IDEs, MCP tools, and coding agents.

Avoid positioning Red Widow as another code scanner or external web pentest
tool. The important object is the developer workflow: the IDE runtime,
extensions, agents, MCP tools, repo files, CI runner, staging environment, and
secrets boundary.

## Product Boundary

There are three distinct security surfaces:

| Surface | Examples | Primary Owner |
| --- | --- | --- |
| Repo and code security | Routes, auth decorators, dependency usage, secrets handling, agent tool definitions. | Skylos |
| Running app/API security | SQL injection, XSS, SSRF, auth bypass, API abuse against a live target. | Shannon-like tools |
| Developer workflow security | VSIX extensions, MCP servers, coding agents, prompt-injection files, CI workflows, dev containers, staging secrets. | Red Widow |

Red Widow should not become a generic external attacker for running web apps.
That overlaps with web/API pentesting. Red Widow should test whether the path
from developer workflow to production can be abused.

## Skylos And Red Widow

Skylos and Red Widow should be paired but not collapsed into the same product.

| Product | Role | Output |
| --- | --- | --- |
| Skylos | Static attack-surface map. | Routes, auth, agent tools, MCP servers, prompt construction, package scripts, CI workflows, VSIX permissions, dangerous file access. |
| Red Widow | Sandboxed exploit-path proof. | Canary reads, network exfiltration, subprocess attempts, unsafe tool calls, CI secret leaks, replayable policy violation traces. |

The product sentence:

> Skylos maps risky developer-workflow surfaces. Red Widow safely proves whether
> they can steal secrets, cross trust boundaries, or trigger unsafe actions.

## First Product Modules

The first modules should stay narrow and concrete:

| Module | Target | What It Proves |
| --- | --- | --- |
| `redwidow-vsix` | VS Code-compatible extensions. | Extension activation can read secrets, spawn processes, call unknown domains, bundle credentials, or exfiltrate canaries. |
| `redwidow-mcp` | MCP servers and tool policies. | Tools can over-read files, cross path boundaries, call the network, leak secrets, or execute unsafe actions. |
| `redwidow-agent` | AI coding agents and prompts. | Untrusted repo content can influence tool use, leak canaries, bypass policy, or trigger unsafe commands. |
| `redwidow-ci` | GitHub Actions and CI workflows. | Workflows can expose secrets, run untrusted code with privileged tokens, or leak canaries through logs/network. |
| `redwidow-devenv` | Dev containers, package scripts, and local bootstrap config. | Setup paths can run unexpected commands, access credentials, or weaken workspace trust boundaries. |

## Current State

The current CLI already covers the first useful wedge, `redwidow-vsix`:

| Capability | Status |
| --- | --- |
| Scan `.vsix` packages | Built |
| Scan unpacked extension directories | Built |
| Discover locally installed VS Code-compatible extensions | Built |
| Inventory output | Built |
| Static risk findings | Built |
| VSIX webview, terminal, env sweep, executable download chain, and workspace trust findings | Built |
| Extension update diff | Built |
| Extension lockfile | Built |
| Lockfile v2 approval metadata | Built |
| Local VSIX and extension recommendation gate | Built |
| Marketplace/OpenVSX recommendation resolution | Built |
| Approval lockfile flow for resolved IDE extensions | Built |
| Policy-as-code | Built |
| Baseline suppression | Built |
| SARIF output | Built |
| Dynamic canary harness | Built |
| Dynamic terminal, webview, and canary env instrumentation | Built |
| Deterministic faulty VSIX fixture generator | Built |
| Versioned machine-readable JSON fields | Built |
| Cursor/Windsurf AI-IDE workflow config gate | Built |
| VS Code MCP, task/debug/settings workflow gate | Built |
| VSIX language model tool detection | Built |
| Workspace Trust metadata precision | Built |
| AI coding-agent canary probe seed/check | Built |
| First-party gate action and PR CI workflow | Built |
| Update-diff action examples | Pending |
| Strict CI mode for scan errors and truncation warnings | Built |
| Dynamic `run --strict` harness blocking | Built |

The next work should make these capabilities reliable to install, easy to run in
CI, and precise enough that security teams can trust the signal.

VS Code-compatible AI workflow surfaces should stay ahead of new unrelated IDE
ecosystems because they share the existing extension lane while adding
agent-specific trust boundaries: MCP config, language model tools, repo task and
debug config, agent rules, terminal automation, hooks, and ignore/indexing
config. JetBrains and other plugin ecosystems should come after this AI-IDE
profile layer is reliable.

## Phase 1: Production-Ready OSS CLI

Goal: make `red-widow` installable, repeatable, and credible as a standalone
security tool.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| Packaging | Build wheels/sdists and publishable metadata. | `pipx install red-widow` or equivalent works on macOS, Linux, and Windows. |
| CI | GitHub Actions test matrix for Python versions and Node harness tests. | Tests run on every PR with static and dynamic coverage. |
| Stable output | Versioned JSON schema for scan, inventory, diff, gate, and dynamic reports. | Downstream CI can parse output without chasing field churn. |
| Fixtures | Safe generated VSIX fixtures for secrets, native binaries, lifecycle scripts, child process usage, and dynamic canary exfiltration. | Manual demo and automated tests use the same fixture builder. |
| Docs | Short examples for scan, diff, lockfile, policy, baseline, SARIF, and dynamic run. | A new user can run a risky fixture and understand every finding. |
| Exit codes | Document and test success, scan error, policy block, lockfile block, and dynamic block behavior. | CI users can rely on `0`, `1`, and `2` consistently. |
| Performance | Stream large packages, cap pathological archives, and report skipped or truncated content clearly. | Large or hostile VSIX files fail safely or scan predictably. |

Immediate backlog:

1. Expand packaging smoke coverage across published install paths.
2. Add update-diff and changed-workflow examples to `docs/ci.md`.
3. Keep `--strict` mode wired through new CI, action, and editor workflows.
4. Add signed approval records for lockfile entries once the metadata format has settled.
5. Expand installable package smoke tests to cover marketplace cache and fixture demo paths.

## Phase 2: Update Gate And CI Workflow

Goal: make Red Widow useful before extension, agent, and workflow changes reach
developers or CI runners.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| GitHub Action | First-party gate/inventory action with policy, lockfile, and SARIF; update-diff examples still pending. | A repo can block risky extension and AI-IDE workflow changes in CI with one workflow file. |
| Lockfile v2 | Include source marketplace, publisher, version, hash, approval metadata, and last-reviewed timestamp. | Teams can approve exact extension versions and detect drift. |
| Diff reports | More explicit "new risk in this update" output. | The diff view answers why an update should be blocked. |
| PR annotations | Markdown and SARIF summaries for changed findings. | Reviewers see actionable findings in GitHub. |
| Baseline workflow | Baseline only existing risk while failing on new risk. | Teams can adopt Red Widow without boiling the ocean. |
| Workflow gate | Detect changes to extension recommendations, MCP config, agent config, devcontainer config, and CI workflows. | PRs that change developer-workflow trust boundaries are tested before merge. |
| AI-IDE profiles | Treat VS Code, Cursor, and Windsurf as first-class profiles on top of VS Code-compatible extension scanning. | `red-widow gate` reports workspace MCP, tasks, launch config, settings, rules, hooks, and AI workflow config without editor-specific flags. |

This is the strongest open-source wedge because it turns a broad risk score into
a concrete update decision.

## Phase 3: MCP And Agent Harnesses

Goal: move beyond VSIX and prove risky behavior in MCP servers and AI coding
agents.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| MCP inventory | Parse MCP server config from common editor and agent locations. | Red Widow can list configured MCP servers, transports, command args, and exposed tools. |
| MCP sandbox | Run an MCP server with fake workspace files, fake tokens, and policy wrappers around filesystem/network/process access. | Reports show canary reads, network calls, subprocesses, and path-boundary violations. |
| Tool policy tests | Generate safe tool-call scenarios from Skylos or local config. | Red Widow can prove whether a tool can read outside allowed paths or leak data. |
| Prompt-injection fixtures | Seed repo docs/issues/comments with hidden instructions and canary data. | Agent runs show whether untrusted repo content can influence unsafe tool use. |
| Agent harness | Run coding-agent workflows with canary files and monitored tool calls. | Reports include replayable traces for unsafe commands, secret reads, or exfiltration attempts. |

This is the main differentiation from external pentesting: the target is the
developer-workflow trust boundary, not the production HTTP surface.

## Phase 4: Marketplace Intelligence

Goal: understand where an extension came from and whether the package looks
trustworthy before install or update.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| Marketplace fetch | Download and scan packages from VS Code Marketplace and OpenVSX by extension ID/version. | `red-widow scan ms-python.python@x.y.z` works without manual VSIX download. |
| Publisher metadata | Capture publisher, source, install count where available, release dates, and marketplace URL. | Inventory separates marketplace, OpenVSX, and sideloaded packages. |
| Update monitor | Check installed or locked extensions for newer versions and scan diffs. | Teams can see what the next update would add before allowing it. |
| Typosquat and clone signals | Basic similarity checks against approved/popular extension IDs and display names. | Obvious clone packages get review findings. |
| Domain reputation hooks | Policy-aware domain review, including allow and block lists. | Unknown or newly introduced domains are highlighted in update reports. |

Do not overbuild reputation scoring early. The valuable report is still "this
version added this behavior."

## Phase 5: CI, Dev Container, And Staging Workflow Proof

Goal: test abuse paths that sit between repo merge and production deployment.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| CI workflow scanner | Detect risky GitHub Actions triggers, secret exposure, unpinned actions, pull-request token risks, and shell/script boundaries. | PR checks identify workflows that can leak or misuse privileged tokens. |
| CI canary runs | Execute safe workflow simulations with canary secrets and monitored logs/network. | Reports prove whether canaries reach logs, artifacts, or outbound requests. |
| Devcontainer scanner | Parse devcontainer config, features, mounts, lifecycle commands, and privileged settings. | Red Widow flags bootstrap paths that can access host secrets or run unexpected commands. |
| Package script proof | Run install/bootstrap scripts in a canary workspace. | Reports show file reads, process spawns, network calls, and secret exfiltration attempts. |
| Staging boundary checks | Validate staging configs and deploy workflows for secret exposure and unsafe tool access. | Red Widow catches pre-production leakage without becoming a production web pentester. |

This phase should focus on developer-to-production exploit paths, not external
app exploitation.

## Phase 6: Team Inventory And Policy Distribution

Goal: give teams visibility across developer machines and developer-workflow
tools without jumping straight to endpoint enforcement.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| Inventory bundle | A JSON or SQLite inventory format for many machines. | Security can answer which extensions, MCP servers, agents, and workflow configs exist across a fleet. |
| Collector mode | Local command that emits inventory to stdout or a file for MDM/CI collection. | Works with existing device-management tools. |
| Policy bundles | Signed or pinned policy packs for org-wide rules. | Developers and CI use the same policy source. |
| Alerts | Slack/webhook/Jira output for blocked updates and new critical findings. | Security teams can triage without reading raw JSON. |
| Dashboard seed | Static HTML or small server that reads inventory and scan results. | No heavy SaaS required to prove the workflow. |

This phase should stay developer-native and lightweight. Endpoint platforms can
collect the output before Red Widow needs its own agent.

## Phase 7: Approval Workflow And Private Marketplace

Goal: move from detection to controlled installation and update gating.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| Approval records | Signed approvals tied to extension ID, version, source, and hash. | A lockfile can prove who approved what and when. |
| Review queue | Simple UI or API for extension approval requests. | Developers can request an extension without bypassing security. |
| Marketplace proxy | Proxy VS Code Marketplace/OpenVSX package downloads through Red Widow. | Updates can be delayed until scanned and approved. |
| Enterprise config | Generate VS Code-compatible policy snippets where possible. | Teams can enforce allowed extensions with existing controls. |
| Private catalog | Approved extension catalog with risk summaries and approved alternatives. | Developers know which extensions are safe to install. |
| Tool catalog | Approved MCP servers, agent tools, and CI templates with policy summaries. | Developers know which workflow tools are safe to use. |

This is where the product becomes more than a CLI. It also starts to compete on
enterprise workflow instead of scanner depth alone.

## Phase 8: Runtime Monitoring And Enforcement

Goal: attribute risky behavior to the extension that caused it and block the
behavior when needed.

| Workstream | Deliverable | Release Criteria |
| --- | --- | --- |
| Stronger sandboxing | Run dynamic analysis in isolated CI containers or VMs. | Unknown hostile packages can be tested without trusting the harness alone. |
| Runtime attribution | Map process, filesystem, network, and tool-call events back to an extension, MCP server, agent, or workflow. | Reports say which component caused the behavior. |
| Endpoint agent | Optional agent for process/network/file monitoring. | Teams can monitor installed extensions after approval. |
| Network controls | Proxy or block suspicious extension-originated requests. | Unknown domains can be denied or reviewed. |
| Agent and MCP coverage | Extend checks to IDE agents, MCP servers, and tool plugins. | Red Widow covers the modern AI IDE runtime, not just classic extensions. |

This phase is technically harder and should wait until the scanner, update gate,
and approval workflow have clear demand.

## Non-Goals For Now

- Do not build a generic SQL injection or SAST plugin.
- Do not promise the dynamic harness is a full OS sandbox.
- Do not compete directly with external web/API pentesting as the core product.
- Do not start with a full enterprise dashboard before the CLI and CI workflow
  are sharp.
- Do not make AI the core pitch. AI increases the risk, but the product is IDE
  supply-chain security.

## Success Metrics

| Metric | Why It Matters |
| --- | --- |
| Extensions scanned per week | Measures real usage of the CLI and CI flow. |
| Update diffs generated | Measures the core wedge, not just one-off scans. |
| Blocks with actionable findings | Measures whether reports are specific enough to act on. |
| False-positive review rate | Keeps the scanner useful for developers. |
| Lockfiles adopted | Shows teams are moving from visibility to enforcement. |
| Inventory coverage by editor | Shows cross-editor value beyond VS Code alone. |
| MCP and agent runs with replayable traces | Measures progress toward developer-workflow exploit proof. |
| CI and devcontainer boundary violations caught | Measures coverage beyond VSIX packages. |

## Recommended Next Builds

1. Package and release the CLI properly.
2. Add a GitHub Action with SARIF, update-diff examples, and workflow-change
   gates.
3. Build `redwidow-agent`: move from transcript checking to monitored agent
   runs with canary files, untrusted repo content, and replayable tool-call
   traces.
4. Build `redwidow-mcp`: inventory MCP configs, run a local MCP server in a
   canary sandbox, and report file/network/process boundary violations.
