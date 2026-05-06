# Red Widow VS Code Extension

This extension runs the local `red-widow` CLI against the current workspace and
surfaces the gate decision inside VS Code.

## Features

- Runs `red-widow gate --format json` from the active workspace.
- Shows `PASS`, `REVIEW`, `BLOCK`, or error state in the status bar.
- Creates Problems diagnostics for blocking and review findings.
- Watches common AI IDE workflow files such as `.vscode/mcp.json`,
  `.vscode/extensions.json`, `.cursor/rules`, `.cursorrules`, `AGENTS.md`, and
  Windsurf config.
- Provides `Red Widow: Run Gate` and `Red Widow: Open Last Report` commands.

## Local Development

Install the Python CLI first:

```bash
python3 -m pip install -e ..
```

Open this `vscode-extension/` folder in VS Code and press `F5` to launch an
Extension Development Host.

When running from this repository instead of an installed CLI, set:

```json
{
  "redWidow.cliPath": "python3",
  "redWidow.cliArgs": ["-m", "red_widow"]
}
```

Run a syntax check:

```bash
npm test
```
