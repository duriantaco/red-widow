from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


MAX_TEXT_BYTES = 512_000
EDITOR_CURSOR = "Cursor"
EDITOR_VSCODE = "VS Code"
EDITOR_WINDSURF = "Windsurf"
PROCESS_ENV_LITERAL = "process.env"
RULE_MCP_ENV_USAGE = "mcp-env-" + "secret"
SEVERITY_MEDIUM = "medium"
CURSOR_DIR = ".cursor"
VSCODE_DIR = ".vscode"
WINDSURF_DIR = ".windsurf"
RULES_LABEL = "rules"
MCP_SERVER_LABEL = "MCP server"
SHELL_TASK_TYPES = {"shell"}
SECRET_ENV_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL|AUTH|API_KEY)", re.IGNORECASE)
SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
SAFE_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
PUBLIC_RELAY_HOST_MARKERS = ("ngrok", "trycloudflare", "localhost.run", "loca.lt", "localtunnel")
SECRET_FILE_MARKERS = (
    ".env",
    ".npmrc",
    ".netrc",
    ".git-credentials",
    ".ssh/id_rsa",
    "id_rsa",
    ".aws/credentials",
    "google_application_credentials",
)
AGENT_DANGER_PATTERNS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "exfiltrate",
    "send secrets",
    "steal secrets",
    "read ~/.ssh",
    "cat ~/.ssh",
    "cat .env",
    "print env",
    "dump env",
    PROCESS_ENV_LITERAL,
    "curl ",
    "| bash",
    "bash -c",
    "sh -c",
)


@dataclass(frozen=True)
class AiIdeItem:
    rule_id: str
    message: str
    severity: str
    target: str
    detail: str
    blocking: bool = False


@dataclass(frozen=True)
class _McpCommand:
    path: Path
    editor: str
    name: str
    command: str
    args: list[str]
    server: dict[str, Any]


def scan_ai_ide_workflow(
    workspaces: Iterable[str | Path],
    *,
    include_global: bool = False,
) -> list[AiIdeItem]:
    items: list[AiIdeItem] = []
    seen_paths: set[Path] = set()
    for workspace in workspaces:
        workspace_path = Path(workspace).expanduser()
        if not workspace_path.is_dir():
            continue
        items.extend(_scan_workspace(workspace_path, seen_paths))

    if include_global:
        items.extend(_scan_global_configs(seen_paths))

    return items


def _scan_workspace(workspace: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    items: list[AiIdeItem] = []
    items.extend(_scan_mcp_config(workspace / VSCODE_DIR / "mcp.json", EDITOR_VSCODE, seen_paths))
    items.extend(_scan_mcp_config(workspace / CURSOR_DIR / "mcp.json", EDITOR_CURSOR, seen_paths))
    items.extend(
        _scan_mcp_config(
            workspace / ".codeium" / "windsurf" / "mcp_config.json",
            EDITOR_WINDSURF,
            seen_paths,
        )
    )
    items.extend(_scan_windsurf_hooks(workspace / WINDSURF_DIR / "hooks.json", seen_paths))
    items.extend(_scan_agent_file(workspace / ".cursorrules", f"{EDITOR_CURSOR} {RULES_LABEL}", seen_paths))
    items.extend(_scan_agent_file(workspace / "AGENTS.md", "agent instructions", seen_paths))
    items.extend(_scan_agent_dir(workspace / CURSOR_DIR / "rules", f"{EDITOR_CURSOR} {RULES_LABEL}", seen_paths))
    items.extend(_scan_agent_dir(workspace / WINDSURF_DIR / "rules", f"{EDITOR_WINDSURF} {RULES_LABEL}", seen_paths))
    items.extend(_scan_agent_dir(workspace / WINDSURF_DIR / "workflows", f"{EDITOR_WINDSURF} workflows", seen_paths))
    items.extend(_scan_vscode_tasks(workspace / VSCODE_DIR / "tasks.json", seen_paths))
    items.extend(_scan_vscode_launch(workspace / VSCODE_DIR / "launch.json", seen_paths))
    items.extend(_scan_vscode_settings(workspace / VSCODE_DIR / "settings.json", seen_paths))
    items.extend(_scan_codeiumignore(workspace / ".codeiumignore", seen_paths))
    return items


def _scan_global_configs(seen_paths: set[Path]) -> list[AiIdeItem]:
    home = Path.home()
    items: list[AiIdeItem] = []
    for path in _vscode_user_config_paths("mcp.json"):
        items.extend(_scan_mcp_config(path, EDITOR_VSCODE, seen_paths))
    items.extend(_scan_mcp_config(home / CURSOR_DIR / "mcp.json", EDITOR_CURSOR, seen_paths))
    items.extend(_scan_mcp_config(home / ".codeium" / "windsurf" / "mcp_config.json", EDITOR_WINDSURF, seen_paths))
    return items


def _scan_mcp_config(path: Path, editor: str, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    payload = _read_json_config(path, editor, "MCP config")
    if isinstance(payload, AiIdeItem):
        return [payload]

    items = [_config_detected(path, f"{editor} MCP config")]
    for name, server in _mcp_servers(payload):
        if not isinstance(server, dict):
            continue
        items.extend(_mcp_server_items(path, editor, name, server))
    return items


def _read_json_config(path: Path, editor: str, label: str) -> dict[str, Any] | AiIdeItem:
    try:
        text = path.read_text(encoding="utf-8")
        payload = _loads_json_or_jsonc(text)
    except (OSError, json.JSONDecodeError) as exc:
        return AiIdeItem(
            rule_id="ai-ide-config-invalid",
            message=f"{editor} {label} could not be parsed",
            severity=SEVERITY_MEDIUM,
            target=str(path),
            detail=str(exc),
            blocking=False,
        )
    if not isinstance(payload, dict):
        return AiIdeItem(
            rule_id="ai-ide-config-invalid",
            message=f"{editor} {label} must contain a JSON object",
            severity=SEVERITY_MEDIUM,
            target=str(path),
            detail="top-level JSON value is not an object",
            blocking=False,
        )
    return payload


def _loads_json_or_jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(_strip_jsonc(text))


def _strip_jsonc(text: str) -> str:
    stripped: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            stripped.append(char)
            escaped = (char == "\\" and not escaped)
            if char == '"' and not escaped:
                in_string = False
            elif char != "\\":
                escaped = False
            index += 1
            continue
        if char == '"':
            in_string = True
            stripped.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index = text.find("\n", index)
            if index == -1:
                break
            stripped.append("\n")
            index += 1
            continue
        if char == "/" and next_char == "*":
            end = text.find("*/", index + 2)
            index = len(text) if end == -1 else end + 2
            continue
        stripped.append(char)
        index += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(stripped))


def _mcp_servers(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    servers: list[tuple[str, dict[str, Any]]] = []
    for key in ("mcpServers", "servers"):
        value = payload.get(key)
        if not isinstance(value, dict):
            continue
        for name, server in value.items():
            if isinstance(name, str) and isinstance(server, dict):
                servers.append((name, server))
    return servers


def _mcp_server_items(path: Path, editor: str, name: str, server: dict[str, Any]) -> list[AiIdeItem]:
    items: list[AiIdeItem] = []
    command = _string_value(server.get("command"))
    args = _string_list(server.get("args"))
    url = _string_value(server.get("url") or server.get("endpoint"))
    env = server.get("env")

    if command:
        items.append(_mcp_command_item(_McpCommand(path, editor, name, command, args, server)))
    if url:
        items.append(_mcp_url_item(path, editor, name, url))
    if isinstance(env, dict):
        items.extend(_mcp_env_items(path, editor, name, env))
    if _has_env_file(server, args):
        items.append(
            AiIdeItem(
                rule_id=RULE_MCP_ENV_USAGE,
                message=_mcp_server_message(editor, name, "uses an env file"),
                severity="high",
                target=str(path),
                detail="env file or --env-file argument can expose broad local secrets",
                blocking=True,
            )
        )
    return items


def _mcp_command_item(context: _McpCommand) -> AiIdeItem:
    reason = _blocking_command_reason(context)
    blocking = bool(reason)
    return AiIdeItem(
        rule_id="mcp-stdio-command",
        message=_mcp_server_message(context.editor, context.name, "launches a local command"),
        severity="high" if blocking else SEVERITY_MEDIUM,
        target=str(context.path),
        detail=reason or f"command={_redacted_command(context.command, context.args)}",
        blocking=blocking,
    )


def _blocking_command_reason(context: _McpCommand) -> str:
    command_name = Path(context.command).name.lower()
    command_text = _joined_command(context.command, context.args).lower()
    reason = ""
    if command_name in SHELL_COMMANDS:
        reason = f"shell wrapper command={_redacted_command(context.command, context.args)}"
    elif re.search(r"\b(curl|wget)\b.*\|.*\b(bash|sh|zsh)\b", command_text):
        reason = f"download-to-shell pipeline command={_redacted_command(context.command, context.args)}"
    elif any(marker in command_text for marker in SECRET_FILE_MARKERS):
        reason = f"command references a sensitive local file: {_redacted_command(context.command, context.args)}"
    elif _has_broad_env(context.server):
        reason = "server config appears to pass a broad environment set"
    return reason


def _mcp_url_item(path: Path, editor: str, name: str, url: str) -> AiIdeItem:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    blocking = False
    detail = f"url={_redact_url(url)}"
    if parsed.scheme != "https" and host not in SAFE_LOCAL_HOSTS:
        blocking = True
        detail = f"non-HTTPS remote MCP URL: {_redact_url(url)}"
    elif any(marker in host for marker in PUBLIC_RELAY_HOST_MARKERS):
        blocking = True
        detail = f"public relay MCP URL: {_redact_url(url)}"
    return AiIdeItem(
        rule_id="mcp-remote-url",
        message=_mcp_server_message(editor, name, "uses a remote URL"),
        severity="high" if blocking else SEVERITY_MEDIUM,
        target=str(path),
        detail=detail,
        blocking=blocking,
    )


def _mcp_env_items(path: Path, editor: str, name: str, env: dict[Any, Any]) -> list[AiIdeItem]:
    secret_keys = sorted(str(key) for key in env if SECRET_ENV_RE.search(str(key)))
    items: list[AiIdeItem] = []
    if secret_keys:
        items.append(
            AiIdeItem(
                rule_id=RULE_MCP_ENV_USAGE,
                message=_mcp_server_message(editor, name, "references secret-like env vars"),
                severity=SEVERITY_MEDIUM,
                target=str(path),
                detail="env keys: " + ", ".join(secret_keys[:8]),
                blocking=False,
            )
        )
    if any(_looks_like_broad_env_value(value) for value in env.values()):
        items.append(
            AiIdeItem(
                rule_id=RULE_MCP_ENV_USAGE,
                message=_mcp_server_message(editor, name, "appears to pass broad environment values"),
                severity="high",
                target=str(path),
                detail="env value references process.env or wildcard environment expansion",
                blocking=True,
            )
        )
    return items


def _mcp_server_message(editor: str, name: str, action: str) -> str:
    return f"{editor} {MCP_SERVER_LABEL} {name} {action}"


def _scan_vscode_tasks(path: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    payload = _read_json_config(path, EDITOR_VSCODE, "tasks config")
    if isinstance(payload, AiIdeItem):
        return [payload]

    items = [_config_detected(path, "VS Code tasks")]
    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        return items
    for task in tasks:
        if isinstance(task, dict):
            item = _vscode_task_item(path, task)
            if item:
                items.append(item)
    return items


def _vscode_task_item(path: Path, task: dict[str, Any]) -> AiIdeItem | None:
    command = _string_value(task.get("command"))
    if not command:
        return None
    args = _string_list(task.get("args"))
    label = _string_value(task.get("label") or task.get("type")) or "<unnamed>"
    detail = _workflow_command_blocking_reason(command, args)
    task_type = _string_value(task.get("type")).lower()
    if not detail and task_type in SHELL_TASK_TYPES:
        detail = _shell_chain_detail(command, args)
    if detail:
        return AiIdeItem(
            rule_id="vscode-task-shell-execution",
            message=f"VS Code task {label} runs a risky shell command",
            severity="high",
            target=str(path),
            detail=detail,
            blocking=True,
        )
    return AiIdeItem(
        rule_id="vscode-task-command",
        message=f"VS Code task {label} runs a command",
        severity=SEVERITY_MEDIUM,
        target=str(path),
        detail=f"command={_redacted_command(command, args)}",
        blocking=False,
    )


def _scan_vscode_launch(path: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    payload = _read_json_config(path, EDITOR_VSCODE, "launch config")
    if isinstance(payload, AiIdeItem):
        return [payload]

    items = [_config_detected(path, "VS Code launch config")]
    configurations = payload.get("configurations")
    if not isinstance(configurations, list):
        return items
    for config in configurations:
        if isinstance(config, dict):
            items.extend(_vscode_launch_items(path, config))
    return items


def _vscode_launch_items(path: Path, config: dict[str, Any]) -> list[AiIdeItem]:
    items: list[AiIdeItem] = []
    label = _string_value(config.get("name") or config.get("type")) or "<unnamed>"
    env_file = _string_value(config.get("envFile"))
    if env_file:
        secret_detail = _secret_file_detail(env_file)
        items.append(
            AiIdeItem(
                rule_id="vscode-launch-env-file",
                message=f"VS Code launch config {label} loads an env file",
                severity="high" if secret_detail and ".env" not in env_file.lower() else SEVERITY_MEDIUM,
                target=str(path),
                detail=secret_detail or f"envFile={_redacted_text(env_file)}",
                blocking=bool(secret_detail and ".env" not in env_file.lower()),
            )
        )

    runtime = _string_value(config.get("runtimeExecutable") or config.get("program"))
    args = _string_list(config.get("runtimeArgs") or config.get("args"))
    if runtime:
        detail = _workflow_command_blocking_reason(runtime, args)
        if detail:
            items.append(
                AiIdeItem(
                    rule_id="vscode-config-command-risk",
                    message=f"VS Code launch config {label} runs a risky executable",
                    severity="high",
                    target=str(path),
                    detail=detail,
                    blocking=True,
                )
            )
    env = config.get("env")
    if isinstance(env, dict):
        items.extend(_vscode_secret_env_items(path, label, env))
    return items


def _scan_vscode_settings(path: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    payload = _read_json_config(path, EDITOR_VSCODE, "settings config")
    if isinstance(payload, AiIdeItem):
        return [payload]

    items = [_config_detected(path, "VS Code settings")]
    for key, value in _flatten_config(payload):
        if not _setting_key_can_affect_execution(key):
            continue
        rendered = _render_config_value(value)
        if not rendered:
            continue
        command_detail = _shell_execution_detail(rendered)
        secret_detail = _secret_file_detail(rendered)
        if command_detail:
            items.append(
                AiIdeItem(
                    rule_id="vscode-config-command-risk",
                    message=f"VS Code setting {key} can influence command execution",
                    severity="high",
                    target=str(path),
                    detail=command_detail,
                    blocking=True,
                )
            )
        elif secret_detail:
            items.append(
                AiIdeItem(
                    rule_id="vscode-config-secret-risk",
                    message=f"VS Code setting {key} references sensitive-looking files",
                    severity=SEVERITY_MEDIUM,
                    target=str(path),
                    detail=secret_detail,
                    blocking=False,
                )
            )
    return items


def _vscode_secret_env_items(path: Path, label: str, env: dict[Any, Any]) -> list[AiIdeItem]:
    secret_keys = sorted(str(key) for key in env if SECRET_ENV_RE.search(str(key)))
    if not secret_keys:
        return []
    return [
        AiIdeItem(
            rule_id="vscode-config-secret-risk",
            message=f"VS Code launch config {label} sets secret-like env vars",
            severity=SEVERITY_MEDIUM,
            target=str(path),
            detail="env keys: " + ", ".join(secret_keys[:8]),
            blocking=False,
        )
    ]


def _flatten_config(payload: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    flattened: list[tuple[str, Any]] = []
    for key, value in payload.items():
        key_path = f"{prefix}.{key}" if prefix else str(key)
        flattened.append((key_path, value))
        if isinstance(value, dict):
            flattened.extend(_flatten_config(value, key_path))
    return flattened


def _setting_key_can_affect_execution(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("command", "executable", "runtime", "path", "args", "envfile"))


def _render_config_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(item for item in value if isinstance(item, str))
    return ""


def _workflow_command_blocking_reason(command: str, args: list[str]) -> str:
    command_name = Path(command).name.lower()
    if command_name in SHELL_COMMANDS:
        return f"shell wrapper command={_redacted_command(command, args)}"
    return _workflow_text_blocking_reason(_joined_command(command, args))


def _workflow_text_blocking_reason(text: str) -> str:
    execution_detail = _shell_execution_detail(text)
    if execution_detail:
        return execution_detail
    secret_detail = _secret_file_detail(text)
    if secret_detail:
        return secret_detail
    return ""


def _shell_execution_detail(text: str) -> str:
    lowered = text.lower()
    if re.search(r"\b(curl|wget)\b.*\|.*\b(bash|sh|zsh)\b", lowered):
        return f"download-to-shell pipeline: {_redacted_text(text)}"
    if re.search(r"\b(bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)\b\s+(-c|/c)\b", lowered):
        return f"shell command wrapper: {_redacted_text(text)}"
    return ""


def _shell_chain_detail(command: str, args: list[str]) -> str:
    text = _joined_command(command, args)
    if re.search(r"(&&|\|\||;|\|)", text):
        return f"shell command chain: {_redacted_text(text)}"
    return ""


def _secret_file_detail(text: str) -> str:
    lowered = text.lower()
    for marker in SECRET_FILE_MARKERS:
        if marker in lowered:
            return f"references sensitive local file: {_redacted_text(text)}"
    return ""


def _vscode_user_config_paths(filename: str) -> list[Path]:
    home = Path.home()
    paths = [
        home / ".config" / "Code" / "User" / filename,
        home / ".config" / "Code - Insiders" / "User" / filename,
        home / "Library" / "Application Support" / "Code" / "User" / filename,
        home / "Library" / "Application Support" / "Code - Insiders" / "User" / filename,
        home / "AppData" / "Roaming" / "Code" / "User" / filename,
        home / "AppData" / "Roaming" / "Code - Insiders" / "User" / filename,
    ]
    return paths


def _scan_windsurf_hooks(path: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    payload = _read_json_config(path, "Windsurf", "hooks config")
    if isinstance(payload, AiIdeItem):
        return [payload]
    items = [_config_detected(path, "Windsurf hooks")]
    for command in _commands_from_hooks(payload):
        items.append(
            AiIdeItem(
                rule_id="windsurf-shell-hook",
                message="Windsurf hook runs a shell command",
                severity="high",
                target=str(path),
                detail=f"command={_redacted_text(command)}",
                blocking=True,
            )
        )
    return items


def _commands_from_hooks(value: Any) -> list[str]:
    commands: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"command", "cmd", "script", "shell"} and isinstance(child, str):
                commands.append(child)
            else:
                commands.extend(_commands_from_hooks(child))
    elif isinstance(value, list):
        for child in value:
            commands.extend(_commands_from_hooks(child))
    return commands


def _scan_agent_dir(path: Path, label: str, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not path.is_dir():
        return []
    items = [_config_detected(path, label)]
    for child in sorted(path.rglob("*")):
        if child.is_file():
            items.extend(_scan_agent_file(child, label, seen_paths, include_detected=False))
    return items


def _scan_agent_file(
    path: Path,
    label: str,
    seen_paths: set[Path],
    *,
    include_detected: bool = True,
) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    items = [_config_detected(path, label)] if include_detected else []
    text = _read_text_sample(path)
    if not text:
        return items
    evidence = _dangerous_agent_evidence(text)
    if evidence:
        items.append(
            AiIdeItem(
                rule_id="agent-rule-dangerous-instruction",
                message=f"{label} contain risky agent instructions",
                severity=SEVERITY_MEDIUM,
                target=str(path),
                detail=evidence,
                blocking=False,
            )
        )
    return items


def _scan_codeiumignore(path: Path, seen_paths: set[Path]) -> list[AiIdeItem]:
    if not _claim_existing_file(path, seen_paths):
        return []
    items = [_config_detected(path, "Windsurf ignore config")]
    text = _read_text_sample(path)
    risky_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("!") and any(marker in line.lower() for marker in SECRET_FILE_MARKERS)
    ]
    if risky_lines:
        items.append(
            AiIdeItem(
                rule_id="ignore-config-risk",
                message="Windsurf ignore config re-includes sensitive-looking files",
                severity=SEVERITY_MEDIUM,
                target=str(path),
                detail="patterns: " + ", ".join(risky_lines[:5]),
                blocking=False,
            )
        )
    return items


def _dangerous_agent_evidence(text: str) -> str:
    lowered = text.lower()
    for pattern in AGENT_DANGER_PATTERNS:
        index = lowered.find(pattern)
        if index == -1:
            continue
        line = _line_containing(text, index)
        return f"matched '{pattern}': {_redacted_text(line)}"
    return ""


def _line_containing(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return text[start:end]


def _config_detected(path: Path, label: str) -> AiIdeItem:
    return AiIdeItem(
        rule_id="ai-ide-config-detected",
        message=f"{label} detected",
        severity="info",
        target=str(path),
        detail="AI IDE workflow config is included in inventory",
        blocking=False,
    )


def _claim_existing_file(path: Path, seen_paths: set[Path]) -> bool:
    if not path.is_file():
        return False
    resolved = path.expanduser().resolve(strict=False)
    if resolved in seen_paths:
        return False
    seen_paths.add(resolved)
    return True


def _read_text_sample(path: Path) -> str:
    try:
        chunks: list[str] = []
        remaining = MAX_TEXT_BYTES
        with path.open("rb") as fh:
            while remaining > 0:
                chunk = fh.readline(min(8192, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                chunks.append(chunk.decode("utf-8", errors="replace"))
        return "".join(chunks)
    except OSError:
        return ""


def _string_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _joined_command(command: str, args: list[str]) -> str:
    return " ".join([command, *args])


def _redacted_command(command: str, args: list[str]) -> str:
    return _redacted_text(_joined_command(command, args))


def _redacted_text(value: str) -> str:
    compact = " ".join(value.split())
    if len(compact) > 180:
        compact = compact[:177] + "..."
    return compact


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.username and not parsed.password:
        return _redacted_text(url)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    redacted = parsed._replace(netloc=f"<redacted>@{host}{port}").geturl()
    return _redacted_text(redacted)


def _has_env_file(server: dict[str, Any], args: list[str]) -> bool:
    env_file = server.get("envFile") or server.get("env_file") or server.get("envFiles")
    if env_file:
        return True
    arg_text = " ".join(args).lower()
    return "--env-file" in arg_text or any(marker in arg_text for marker in SECRET_FILE_MARKERS)


def _has_broad_env(server: dict[str, Any]) -> bool:
    for key in ("env", "environment"):
        value = server.get(key)
        if value in (True, "*", "all", "process.env"):
            return True
        if isinstance(value, str) and _looks_like_broad_env_value(value):
            return True
    return False


def _looks_like_broad_env_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return lowered in {"*", "all", PROCESS_ENV_LITERAL, "${env:*}", "${env}"} or PROCESS_ENV_LITERAL in lowered
