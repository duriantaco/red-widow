const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

const CONFIG_SECTION = "redWidow";
const DIAGNOSTIC_SOURCE = "red-widow";
const OUTPUT_NAME = "Red Widow";
const WATCH_PATTERNS = [
  ".vscode/extensions.json",
  ".vscode/mcp.json",
  ".vscode/tasks.json",
  ".vscode/launch.json",
  ".vscode/settings.json",
  ".cursor/mcp.json",
  ".cursor/rules/**",
  ".cursorrules",
  "AGENTS.md",
  ".windsurf/hooks.json",
  ".windsurf/rules/**",
  ".windsurf/workflows/**",
  ".codeium/windsurf/mcp_config.json",
  ".codeiumignore",
  "*.vsix",
];

let diagnostics;
let output;
let statusBar;
let lastReport = null;
let lastReportText = "";
let running = false;
let rerunRequested = false;
let debounceTimer = undefined;
let watchers = [];

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("red-widow");
  output = vscode.window.createOutputChannel(OUTPUT_NAME);
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 80);
  statusBar.command = "redWidow.openReport";
  statusBar.name = "Red Widow";
  context.subscriptions.push(diagnostics, output, statusBar);

  context.subscriptions.push(vscode.commands.registerCommand("redWidow.runGate", () => runGate({ reveal: true })));
  context.subscriptions.push(vscode.commands.registerCommand("redWidow.openReport", openReport));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration(CONFIG_SECTION)) {
      rebuildWatchers(context);
      scheduleGateRun("configuration changed");
    }
  }));

  rebuildWatchers(context);
  updateStatus("idle");

  if (config().get("runOnStartup", true)) {
    scheduleGateRun("workspace opened", 500);
  }
}

function deactivate() {
  disposeWatchers();
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
}

function rebuildWatchers(context) {
  disposeWatchers();
  if (!config().get("watchWorkspaceConfig", true)) {
    return;
  }
  for (const folder of vscode.workspace.workspaceFolders || []) {
    for (const pattern of WATCH_PATTERNS) {
      const watcher = vscode.workspace.createFileSystemWatcher(
        new vscode.RelativePattern(folder, pattern),
        false,
        false,
        false,
      );
      watcher.onDidCreate((uri) => scheduleGateRun(`created ${shortPath(uri.fsPath)}`));
      watcher.onDidChange((uri) => scheduleGateRun(`changed ${shortPath(uri.fsPath)}`));
      watcher.onDidDelete((uri) => scheduleGateRun(`deleted ${shortPath(uri.fsPath)}`));
      watchers.push(watcher);
      context.subscriptions.push(watcher);
    }
  }
}

function disposeWatchers() {
  for (const watcher of watchers) {
    watcher.dispose();
  }
  watchers = [];
}

function scheduleGateRun(reason, delayMs = 350) {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  debounceTimer = setTimeout(() => {
    debounceTimer = undefined;
    runGate({ reason }).catch((error) => showRunError(error));
  }, delayMs);
}

async function runGate(options = {}) {
  const folder = primaryWorkspaceFolder();
  if (!folder) {
    diagnostics.clear();
    lastReport = null;
    lastReportText = "Open a workspace to run Red Widow.";
    outputLine(lastReportText);
    updateStatus("idle", "No workspace");
    return;
  }

  if (running) {
    rerunRequested = true;
    return;
  }

  running = true;
  updateStatus("running");
  if (options.reveal) {
    output.show(true);
  }
  outputLine(`Running Red Widow gate for ${folder.uri.fsPath}${options.reason ? ` (${options.reason})` : ""}`);

  try {
    const report = await executeGate(folder);
    lastReport = report;
    lastReportText = renderReport(report);
    outputLine(lastReportText);
    applyDiagnostics(folder, report);
    updateStatus("report", report);
  } catch (error) {
    showRunError(error);
  } finally {
    running = false;
    if (rerunRequested) {
      rerunRequested = false;
      scheduleGateRun("queued workspace change", 100);
    }
  }
}

function executeGate(folder) {
  const cfg = config();
  const baseArgs = cfg.get("cliArgs", []);
  const args = Array.isArray(baseArgs) ? baseArgs.filter((item) => typeof item === "string") : [];
  args.push("gate", "--workspace", folder.uri.fsPath, "--format", "json");
  if (cfg.get("offline", true)) {
    args.push("--offline");
  }
  if (cfg.get("failOnReview", false)) {
    args.push("--fail-on-review");
  }
  if (cfg.get("includeInstalled", false)) {
    args.push("--installed");
  }
  const policy = resolveWorkspacePath(folder, cfg.get("policy", ""));
  if (policy) {
    args.push("--policy", policy);
  }
  const lockfile = resolveWorkspacePath(folder, cfg.get("lockfile", ""));
  if (lockfile) {
    args.push("--lockfile", lockfile);
  }

  return new Promise((resolve, reject) => {
    childProcess.execFile(
      cfg.get("cliPath", "red-widow"),
      args,
      {
        cwd: folder.uri.fsPath,
        maxBuffer: 10 * 1024 * 1024,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const parsed = parseGateJson(stdout);
        if (parsed) {
          parsed._exitCode = error && typeof error.code === "number" ? error.code : 0;
          parsed._stderr = stderr || "";
          resolve(parsed);
          return;
        }
        if (error) {
          reject(new Error((stderr || error.message || "red-widow failed").trim()));
          return;
        }
        reject(new Error("red-widow did not return valid JSON"));
      },
    );
  });
}

function parseGateJson(stdout) {
  const text = (stdout || "").trim();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    return null;
  }
}

function applyDiagnostics(folder, report) {
  diagnostics.clear();
  const maxDiagnostics = Math.max(0, Number(config().get("maxDiagnostics", 200)) || 0);
  if (maxDiagnostics === 0) {
    return;
  }

  const byUri = new Map();
  const pushDiagnostic = (filePath, diagnostic) => {
    const uri = diagnosticUri(folder, filePath);
    if (!uri) {
      return;
    }
    const key = uri.toString();
    const existing = byUri.get(key) || [];
    if (existing.length >= maxDiagnostics) {
      return;
    }
    existing.push(diagnostic);
    byUri.set(key, existing);
  };

  for (const item of [...(report.blockingItems || []), ...(report.reviewItems || [])]) {
    pushDiagnostic(item.target, diagnosticForGateItem(item));
  }

  for (const policy of report.policyViolations || []) {
    pushDiagnostic(policy.target, diagnosticForPolicy(policy));
  }

  for (const reportItem of report.reports || []) {
    for (const finding of reportItem.findings || []) {
      pushDiagnostic(findingPath(reportItem, finding), diagnosticForFinding(reportItem, finding));
    }
  }

  let count = 0;
  for (const [uriString, items] of byUri) {
    const remaining = Math.max(0, maxDiagnostics - count);
    if (remaining === 0) {
      break;
    }
    diagnostics.set(vscode.Uri.parse(uriString), items.slice(0, remaining));
    count += items.length;
  }
}

function diagnosticForGateItem(item) {
  const diagnostic = new vscode.Diagnostic(
    wholeFileRange(),
    `${item.ruleId}: ${joinMessage(item.message, item.detail)}`,
    item.blocking ? vscode.DiagnosticSeverity.Error : severityFor(item.severity),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = item.ruleId;
  return diagnostic;
}

function diagnosticForPolicy(policy) {
  const diagnostic = new vscode.Diagnostic(
    wholeFileRange(),
    `policy.${policy.ruleId}: ${joinMessage(policy.message, policy.detail)}`,
    severityFor(policy.severity),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = `policy.${policy.ruleId}`;
  return diagnostic;
}

function diagnosticForFinding(reportItem, finding) {
  const diagnostic = new vscode.Diagnostic(
    wholeFileRange(),
    `${finding.ruleId}: ${joinMessage(`${reportItem.extensionId}: ${finding.title}`, finding.detail)}`,
    finding.blocking ? vscode.DiagnosticSeverity.Error : severityFor(finding.severity),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.ruleId;
  return diagnostic;
}

function findingPath(reportItem, finding) {
  if (finding.path && reportItem.target && isDirectory(reportItem.target)) {
    return path.join(reportItem.target, finding.path);
  }
  return reportItem.target || finding.path || "";
}

function diagnosticUri(folder, maybePath) {
  if (!maybePath) {
    return folder.uri;
  }
  const resolved = path.isAbsolute(maybePath) ? maybePath : path.join(folder.uri.fsPath, maybePath);
  if (!fs.existsSync(resolved)) {
    return folder.uri;
  }
  return vscode.Uri.file(resolved);
}

function wholeFileRange() {
  return new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 1));
}

function severityFor(severity) {
  if (severity === "critical" || severity === "high") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (severity === "medium") {
    return vscode.DiagnosticSeverity.Warning;
  }
  return vscode.DiagnosticSeverity.Information;
}

function updateStatus(state, reportOrMessage) {
  if (!statusBar) {
    return;
  }
  if (state === "running") {
    statusBar.text = "$(sync~spin) Red Widow";
    statusBar.tooltip = "Red Widow gate is running";
    statusBar.backgroundColor = undefined;
    statusBar.show();
    return;
  }
  if (state === "error") {
    statusBar.text = "$(error) Red Widow ERROR";
    statusBar.tooltip = String(reportOrMessage || "Red Widow failed");
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    statusBar.show();
    return;
  }
  if (state === "report") {
    const report = reportOrMessage;
    const decision = String(report.decision || "UNKNOWN");
    statusBar.text = `${iconForDecision(decision)} Red Widow ${decision}`;
    statusBar.tooltip = `${report.reason || "Red Widow gate complete"}\n${summaryLine(report.summary || {})}`;
    statusBar.backgroundColor = decision === "BLOCK"
      ? new vscode.ThemeColor("statusBarItem.errorBackground")
      : decision === "REVIEW"
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;
    statusBar.show();
    return;
  }
  statusBar.text = "$(shield) Red Widow";
  statusBar.tooltip = String(reportOrMessage || "Run Red Widow gate");
  statusBar.backgroundColor = undefined;
  statusBar.show();
}

function iconForDecision(decision) {
  if (decision === "BLOCK") {
    return "$(error)";
  }
  if (decision === "REVIEW") {
    return "$(warning)";
  }
  if (decision === "PASS") {
    return "$(pass)";
  }
  return "$(shield)";
}

function renderReport(report) {
  const summary = report.summary || {};
  const lines = [
    "Red Widow gate",
    `Decision: ${report.decision || "UNKNOWN"} - ${report.reason || ""}`,
    `Summary: ${summaryLine(summary)}`,
  ];
  appendItems(lines, "Blocking items", report.blockingItems || []);
  appendItems(lines, "Review items", report.reviewItems || []);
  appendFindings(lines, report.reports || []);
  if (report.lockfileErrors && report.lockfileErrors.length) {
    lines.push("", "Lockfile errors:");
    for (const error of report.lockfileErrors) {
      lines.push(`  - ${error}`);
    }
  }
  if (report.scanErrors && report.scanErrors.length) {
    lines.push("", "Scan errors:");
    for (const error of report.scanErrors) {
      lines.push(`  - ${error.target}: ${error.error}`);
    }
  }
  if (report._stderr) {
    lines.push("", "stderr:", report._stderr);
  }
  return `${lines.join("\n")}\n`;
}

function appendItems(lines, title, items) {
  if (!items.length) {
    return;
  }
  lines.push("", `${title}:`);
  for (const item of items) {
    const detail = item.detail ? ` - ${item.detail}` : "";
    const target = item.target ? ` (${item.target})` : "";
    lines.push(`  [${String(item.severity || "").toUpperCase()}] ${item.ruleId}: ${item.message}${target}${detail}`);
  }
}

function appendFindings(lines, reports) {
  const findings = [];
  for (const report of reports) {
    for (const finding of report.findings || []) {
      findings.push({ report, finding });
    }
  }
  if (!findings.length) {
    return;
  }
  lines.push("", "Extension findings:");
  for (const { report, finding } of findings.slice(0, 100)) {
    const detail = finding.detail ? ` - ${finding.detail}` : "";
    const where = finding.path ? ` (${finding.path})` : "";
    lines.push(`  [${String(finding.severity || "").toUpperCase()}] ${finding.ruleId}: ${report.extensionId}${where}${detail}`);
  }
  if (findings.length > 100) {
    lines.push(`  ... ${findings.length - 100} more finding(s)`);
  }
}

function openReport() {
  output.show(true);
  if (lastReportText) {
    outputLine(lastReportText);
  } else {
    outputLine("No Red Widow report yet. Run Red Widow: Run Gate.");
  }
}

function showRunError(error) {
  diagnostics.clear();
  lastReport = null;
  lastReportText = `Red Widow failed: ${error.message || error}`;
  outputLine(lastReportText);
  updateStatus("error", error.message || error);
  vscode.window.showWarningMessage(lastReportText);
}

function summaryLine(summary) {
  return [
    `${summary.scannedPackages || 0} scanned`,
    `${summary.blockingItems || 0} blocking`,
    `${summary.reviewItems || 0} review`,
    `${summary.scanErrors || 0} errors`,
  ].join(", ");
}

function outputLine(text) {
  output.appendLine(`[${new Date().toISOString()}]`);
  output.appendLine(text);
}

function config() {
  return vscode.workspace.getConfiguration(CONFIG_SECTION);
}

function primaryWorkspaceFolder() {
  const folders = vscode.workspace.workspaceFolders;
  return folders && folders.length ? folders[0] : undefined;
}

function resolveWorkspacePath(folder, value) {
  if (!value || typeof value !== "string") {
    return "";
  }
  return path.isAbsolute(value) ? value : path.join(folder.uri.fsPath, value);
}

function joinMessage(message, detail) {
  return detail ? `${message} - ${detail}` : message;
}

function shortPath(filePath) {
  const folder = primaryWorkspaceFolder();
  if (!folder) {
    return filePath;
  }
  return path.relative(folder.uri.fsPath, filePath) || filePath;
}

function isDirectory(filePath) {
  try {
    return fs.statSync(filePath).isDirectory();
  } catch (_error) {
    return false;
  }
}

module.exports = {
  activate,
  deactivate,
};
