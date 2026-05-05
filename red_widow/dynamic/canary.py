from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CanaryWorkspace:
    root: Path
    marker: str
    files: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": str(self.root),
            "marker": self.marker,
            "files": self.files,
        }


def create_canary_workspace(root: Path) -> CanaryWorkspace:
    root.mkdir(parents=True, exist_ok=True)
    marker = f"RW_CANARY_{secrets.token_hex(12)}"
    files = {
        ".env": f"RED_WIDOW_SECRET={marker}\nDATABASE_URL=postgres://{marker}@localhost/app\n",
        ".npmrc": f"//registry.npmjs.org/:_authToken={marker}\n",
        ".ssh/id_rsa": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{marker}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        ".vscode/settings.json": json.dumps(
            {
                "redWidow.canary": marker,
                "terminal.integrated.env.osx": {"RW_CANARY_TOKEN": marker},
            },
            indent=2,
        )
        + "\n",
        "README.md": (
            "# Canary Project\n\n"
            "This repository is intentionally fake and belongs to a Red Widow sandbox.\n"
            f"Hidden marker: {marker}\n"
        ),
        "package.json": json.dumps(
            {
                "name": "red-widow-canary-workspace",
                "version": "0.0.0",
                "scripts": {"test": "echo test"},
            },
            indent=2,
        )
        + "\n",
        "src/app.ts": "export const app = 'red-widow-canary';\n",
        "customer-data.json": json.dumps(
            {
                "customer": "Example Corp",
                "apiKey": marker,
            },
            indent=2,
        )
        + "\n",
    }

    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    return CanaryWorkspace(root=root, marker=marker, files={path: str(root / path) for path in files})
