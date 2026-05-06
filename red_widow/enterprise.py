from __future__ import annotations

from typing import Any

from .models import SCHEMA_VERSION


def vscode_allowed_extensions_policy(
    lockfile: dict[str, Any],
    *,
    block_unlisted: bool = True,
    pin_versions: bool = True,
) -> dict[str, Any]:
    allowed = lockfile.get("allowedExtensions")
    if not isinstance(allowed, dict):
        raise ValueError("lockfile is missing an object at allowedExtensions")

    policy: dict[str, Any] = {}
    if block_unlisted:
        policy["*"] = False

    for extension_id, entry in sorted(allowed.items()):
        normalized_id = str(extension_id).lower()
        if pin_versions and isinstance(entry, dict):
            version = entry.get("version")
            if isinstance(version, str) and version:
                policy[normalized_id] = [version]
                continue
        policy[normalized_id] = True

    return {
        "schemaVersion": SCHEMA_VERSION,
        "settings": {
            "extensions.allowed": policy,
        },
    }
