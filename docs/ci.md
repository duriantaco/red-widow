# Red Widow CI

Use the first-party GitHub Action to gate repo workflow risk before extension,
MCP, and AI-IDE changes reach developer machines. The action runs `gate` and
`inventory`: it checks repo config, checked-in non-ignored VSIX packages,
lockfile drift, unresolved recommendations, and SARIF output.

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
          strict: "true"
          fail-on-review: "true"
          upload-sarif: "true"
```

Offline CI does not download marketplace packages. It blocks unresolved
recommendations when `fail-on-review: "true"` is set; set `offline: "false"`
when CI is allowed to download and inspect recommended marketplace packages.
`gate --strict` blocks incomplete static coverage such as scan errors and
truncation warnings. Dynamic sandbox runs use `red-widow run --strict` and are
not part of the GitHub Action yet.

The action writes:

- `red-widow-results/gate.json`
- `red-widow-results/gate.md`
- `red-widow-results/gate.sarif`
- `red-widow-results/inventory.json`
- `red-widow-results/inventory.md`

For local CI scripts, run the same gate directly:

```bash
red-widow gate --workspace . --policy examples/policy.example.json --offline --strict --fail-on-review
red-widow gate --workspace . --policy examples/policy.example.json --offline --strict --fail-on-review --format sarif > red-widow.sarif
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
