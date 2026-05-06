# Red Widow VS Code Extension

The VS Code extension is a thin UI over the existing Red Widow CLI. It keeps the
security logic in Python and uses the editor only for workflow integration.

## What It Does

- Runs `red-widow gate --workspace <folder> --format json`.
- Shows the gate decision in the status bar.
- Adds Problems diagnostics for blocking and review findings.
- Watches VS Code, Cursor, Windsurf, MCP, agent-rule, and checked-in VSIX files.
- Provides commands:
  - `Red Widow: Run Gate`
  - `Red Widow: Open Last Report`

## Local Development

From the repo root:

```bash
python3 -m pip install -e .
```

Then open `vscode-extension/` in VS Code and press `F5`.

When the Python package is not installed, configure the extension development
host to run from the checkout:

```json
{
  "redWidow.cliPath": "python3",
  "redWidow.cliArgs": ["-m", "red_widow"]
}
```

Run the extension syntax check:

```bash
npm --prefix vscode-extension test
```

## Packaging

Package the extension with `vsce` from inside `vscode-extension/`:

```bash
npx @vscode/vsce package
```

The generated VSIX contains only the JavaScript extension wrapper. Users still
need the `red-widow` CLI available on `PATH`, or they must set
`redWidow.cliPath` and `redWidow.cliArgs`.
