# Red Widow CI

Use the first-party GitHub Action to block risky IDE extension, MCP, and AI
developer workflow changes before they reach developer machines.

```yaml
name: Red Widow

on:
  pull_request:
  push:
    branches: [main]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: red-widow/red-widow@v1
        with:
          workspace: .
          policy: examples/policy.example.json
          offline: "true"
          fail-on-review: "true"
          upload-sarif: "true"
```

The action writes:

- `red-widow-results/gate.json`
- `red-widow-results/gate.md`
- `red-widow-results/gate.sarif`
- `red-widow-results/inventory.json`
- `red-widow-results/inventory.md`

For local CI scripts, run the same gate directly:

```bash
red-widow gate --workspace . --policy examples/policy.example.json --offline --fail-on-review
red-widow gate --workspace . --format sarif > red-widow.sarif
red-widow inventory --workspace . --no-installed --format json > red-widow-inventory.json
```

Run with marketplace resolution when CI is allowed to download recommended
extensions from VS Code Marketplace or OpenVSX:

```bash
red-widow gate --workspace . --policy examples/policy.example.json
```

## Approval Flow

Approve exact extension packages into a lockfile:

```bash
red-widow approve --workspace . --reviewed-by security@example.com
```

Future CI runs use `red-widow.lock.json` automatically and block version or
package-hash drift. To enforce the same approved set through VS Code enterprise
controls, export the `extensions.allowed` policy:

```bash
red-widow export vscode-allowed --lockfile red-widow.lock.json --format settings-json
```

The export pins approved extension IDs to lockfile versions and adds an explicit
`"*": false` entry so unapproved extensions are blocked by default.
