#!/usr/bin/env node
"use strict";

const Module = require("module");
const path = require("path");
const stream = require("stream");
const events = require("events");
const url = require("url");

const originalFs = require("fs");
const originalLoad = Module._load;
const config = JSON.parse(process.argv[2] || "{}");
const report = { events: [], errors: [] };
const registeredCommands = [];
const workspaceRoot = originalFs.realpathSync(path.resolve(config.workspaceRoot));
const extensionRoot = originalFs.realpathSync(path.resolve(config.extensionRoot));
const marker = String(config.marker || "");
const patchedPromisesSymbol = Symbol.for("redWidow.fsPromisesPatched");

function record(event) {
  report.events.push({
    kind: String(event.kind || ""),
    operation: String(event.operation || ""),
    target: String(event.target || ""),
    detail: String(event.detail || ""),
    canary: Boolean(event.canary),
    blocked: Boolean(event.blocked),
  });
}

function hasCanary(value) {
  if (!marker) {
    return false;
  }
  if (Buffer.isBuffer(value)) {
    return value.includes(Buffer.from(marker));
  }
  return String(value || "").includes(marker);
}

function envContainsCanary(env) {
  return Object.values(env || {}).some((value) => hasCanary(value));
}

function patchProcessEnv() {
  const originalEnv = process.env;
  const proxy = new Proxy(originalEnv, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof prop === "string" && (prop === "RW_CANARY_TOKEN" || hasCanary(value))) {
        record({
          kind: "env",
          operation: "read",
          target: prop,
          canary: hasCanary(value),
          blocked: false,
        });
      }
      return value;
    },
    ownKeys(target) {
      record({
        kind: "env",
        operation: "enumerate",
        target: "process.env",
        detail: "environment keys enumerated",
        canary: envContainsCanary(target),
        blocked: false,
      });
      return Reflect.ownKeys(target);
    },
  });
  process.env = proxy;
}

function pathFor(input) {
  if (!input) {
    return "";
  }
  if (typeof input === "object" && input.fsPath) {
    return input.fsPath;
  }
  if (Buffer.isBuffer(input)) {
    return input.toString("utf8");
  }
  return String(input);
}

function normalizeFile(input) {
  const raw = pathFor(input);
  if (!raw) {
    return "";
  }
  return path.resolve(raw);
}

function isWorkspacePath(input) {
  const resolved = normalizeFile(input);
  return resolved === workspaceRoot || resolved.startsWith(workspaceRoot + path.sep);
}

function recordFs(operation, input, data, blocked) {
  if (!isWorkspacePath(input)) {
    return;
  }
  record({
    kind: "fs",
    operation,
    target: normalizeFile(input),
    canary: hasCanary(data) || hasCanary(input),
    blocked: Boolean(blocked),
  });
}

function recordReadStream(streamInstance, file) {
  if (!isWorkspacePath(file)) {
    return streamInstance;
  }
  let recorded = false;
  const recordOnce = (data) => {
    if (recorded) {
      return;
    }
    recorded = true;
    recordFs("readStream", file, data || "", false);
  };
  streamInstance.on("data", (chunk) => {
    if (hasCanary(chunk)) {
      recordOnce(chunk);
    }
  });
  streamInstance.on("end", () => recordOnce(""));
  streamInstance.on("error", () => recordOnce(""));
  return streamInstance;
}

function patchFsPromises(fsPromises) {
  if (!fsPromises || fsPromises[patchedPromisesSymbol]) {
    return;
  }
  Object.defineProperty(fsPromises, patchedPromisesSymbol, { value: true });

  const originalPromisesReadFile = fsPromises.readFile;
  if (typeof originalPromisesReadFile === "function") {
    fsPromises.readFile = async function patchedPromisesReadFile(file, ...args) {
      const result = await originalPromisesReadFile.call(this, file, ...args);
      recordFs("readFile", file, result, false);
      return result;
    };
  }

  const originalPromisesWriteFile = fsPromises.writeFile;
  if (typeof originalPromisesWriteFile === "function") {
    fsPromises.writeFile = async function patchedPromisesWriteFile(file, data, ...args) {
      recordFs("writeFile", file, data, false);
      return originalPromisesWriteFile.call(this, file, data, ...args);
    };
  }
}

function patchFs() {
  const fs = require("fs");
  const originalReadFileSync = fs.readFileSync;
  fs.readFileSync = function patchedReadFileSync(file, ...args) {
    const result = originalReadFileSync.call(this, file, ...args);
    recordFs("readFileSync", file, result, false);
    return result;
  };

  const originalReadFile = fs.readFile;
  fs.readFile = function patchedReadFile(file, ...args) {
    const callbackIndex = args.findIndex((item) => typeof item === "function");
    if (callbackIndex !== -1) {
      const callback = args[callbackIndex];
      args[callbackIndex] = function wrappedReadFileCallback(error, data) {
        if (!error) {
          recordFs("readFile", file, data, false);
        }
        return callback.apply(this, arguments);
      };
    }
    return originalReadFile.call(this, file, ...args);
  };

  const originalCreateReadStream = fs.createReadStream;
  fs.createReadStream = function patchedCreateReadStream(file, ...args) {
    return recordReadStream(originalCreateReadStream.call(this, file, ...args), file);
  };

  const originalWriteFileSync = fs.writeFileSync;
  fs.writeFileSync = function patchedWriteFileSync(file, data, ...args) {
    recordFs("writeFileSync", file, data, false);
    return originalWriteFileSync.call(this, file, data, ...args);
  };

  const originalWriteFile = fs.writeFile;
  fs.writeFile = function patchedWriteFile(file, data, ...args) {
    recordFs("writeFile", file, data, false);
    return originalWriteFile.call(this, file, data, ...args);
  };

  patchFsPromises(fs.promises);
  try {
    patchFsPromises(require("fs/promises"));
  } catch {
    // Older Node.js versions may not expose fs/promises as a separate module.
  }
}

function commandFromArgs(args) {
  return args.map((arg) => {
    if (arg === undefined || arg === null) {
      return "";
    }
    if (typeof arg === "string") {
      return arg;
    }
    try {
      return JSON.stringify(arg);
    } catch {
      return String(arg);
    }
  }).join(" ");
}

function fakeChild() {
  const child = new events.EventEmitter();
  child.stdout = new events.EventEmitter();
  child.stderr = new events.EventEmitter();
  child.stdin = new stream.Writable({ write(_chunk, _encoding, callback) { callback(); } });
  child.kill = () => true;
  process.nextTick(() => {
    child.emit("exit", 0, null);
    child.emit("close", 0, null);
  });
  return child;
}

function patchChildProcess() {
  const childProcess = require("child_process");
  for (const operation of ["exec", "execFile", "fork", "spawn", "execSync", "spawnSync"]) {
    childProcess[operation] = function redWidowBlockedProcess(...args) {
      record({
        kind: "child_process",
        operation,
        target: commandFromArgs(args.slice(0, 3)),
        blocked: true,
      });
      const callback = args.find((arg) => typeof arg === "function");
      if (callback) {
        process.nextTick(() => callback(null, "", ""));
      }
      if (operation.endsWith("Sync")) {
        return Buffer.from("");
      }
      return fakeChild();
    };
  }
}

function requestUrl(args) {
  const first = args[0];
  if (typeof first === "string") {
    return first;
  }
  if (first instanceof URL) {
    return first.toString();
  }
  if (first && typeof first === "object") {
    const protocol = first.protocol || "https:";
    const hostname = first.hostname || first.host || "unknown";
    const port = first.port ? `:${first.port}` : "";
    const pathname = first.path || first.pathname || "/";
    return `${protocol}//${hostname}${port}${pathname}`;
  }
  return "unknown";
}

function headersText(headers) {
  if (!headers) {
    return "";
  }
  if (typeof headers.forEach === "function") {
    const values = [];
    headers.forEach((value, key) => values.push(`${key}: ${value}`));
    return values.join("\n");
  }
  if (Array.isArray(headers)) {
    return headers.map((item) => Array.isArray(item) ? item.join(": ") : String(item)).join("\n");
  }
  if (typeof headers === "object") {
    return Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join("\n");
  }
  return String(headers);
}

function requestMetadata(args) {
  const target = requestUrl(args);
  const headerChunks = [];
  for (const arg of args) {
    if (!arg || typeof arg !== "object" || arg instanceof URL || Buffer.isBuffer(arg)) {
      continue;
    }
    if (arg.headers) {
      headerChunks.push(headersText(arg.headers));
    }
  }
  const headers = headerChunks.filter(Boolean).join("\n");
  return { target, headers };
}

function fakeResponse() {
  const response = new stream.Readable({ read() { this.push(null); } });
  response.statusCode = 204;
  response.headers = {};
  return response;
}

function fakeRequest(kind, operation, target, callback, initialDetail, initialCanary) {
  const chunks = [];
  const request = new events.EventEmitter();
  request.write = (chunk, encoding, cb) => {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk || ""), encoding));
    if (typeof cb === "function") {
      cb();
    }
    return true;
  };
  request.end = (chunk, encoding, cb) => {
    if (chunk) {
      request.write(chunk, encoding);
    }
    const body = Buffer.concat(chunks).toString("utf8");
    record({
      kind,
      operation,
      target,
      detail: body ? "request body captured" : initialDetail,
      canary: Boolean(initialCanary) || hasCanary(target) || hasCanary(body),
      blocked: true,
    });
    if (typeof callback === "function") {
      process.nextTick(() => callback(fakeResponse()));
    }
    if (typeof cb === "function") {
      cb();
    }
    process.nextTick(() => {
      request.emit("finish");
      request.emit("close");
    });
    return request;
  };
  request.setHeader = () => {};
  request.getHeader = () => undefined;
  request.removeHeader = () => {};
  request.setTimeout = () => request;
  request.abort = () => request.emit("abort");
  request.destroy = () => request.emit("close");
  return request;
}

function patchNetwork() {
  for (const kind of ["http", "https"]) {
    const mod = require(kind);
    mod.request = function redWidowBlockedRequest(...args) {
      const callback = args.find((arg) => typeof arg === "function");
      const metadata = requestMetadata(args);
      return fakeRequest(
        kind,
        "request",
        metadata.target,
        callback,
        metadata.headers ? "request headers captured" : "",
        hasCanary(metadata.headers)
      );
    };
    mod.get = function redWidowBlockedGet(...args) {
      const callback = args.find((arg) => typeof arg === "function");
      const metadata = requestMetadata(args);
      const request = fakeRequest(
        kind,
        "get",
        metadata.target,
        callback,
        metadata.headers ? "request headers captured" : "",
        hasCanary(metadata.headers)
      );
      request.end();
      return request;
    };
  }

  for (const kind of ["net", "tls"]) {
    const mod = require(kind);
    const connect = function redWidowBlockedConnect(...args) {
      record({
        kind,
        operation: "connect",
        target: commandFromArgs(args.slice(0, 2)),
        blocked: true,
      });
      return fakeChild();
    };
    mod.connect = connect;
    mod.createConnection = connect;
  }

  global.fetch = async function redWidowBlockedFetch(resource, options) {
    const target = resource && resource.url ? resource.url : String(resource || "");
    const body = options && options.body ? options.body : "";
    const headerData = `${headersText(resource && resource.headers)}\n${headersText(options && options.headers)}`;
    record({
      kind: "fetch",
      operation: "fetch",
      target,
      detail: body ? "request body captured" : headerData.trim() ? "request headers captured" : "",
      canary: hasCanary(target) || hasCanary(body) || hasCanary(headerData),
      blocked: true,
    });
    return {
      ok: true,
      status: 204,
      headers: new Map(),
      text: async () => "",
      json: async () => ({}),
      arrayBuffer: async () => new ArrayBuffer(0),
    };
  };
}

function isStrictWebviewCsp(html) {
  const normalized = String(html || "").replace(/\\'/g, "'").replace(/\\"/g, "\"").toLowerCase();
  return normalized.includes("content-security-policy")
    && (normalized.includes("default-src 'none'") || normalized.includes("default-src \"none\""))
    && normalized.includes("script-src");
}

function htmlHasScriptSurface(html, options) {
  return /<script\b/i.test(String(html || "")) || Boolean(options && options.enableScripts === true);
}

function recordWebviewOptions(viewType, options) {
  if (options && options.enableScripts === true) {
    record({
      kind: "webview",
      operation: "enableScripts",
      target: String(viewType || ""),
      detail: "enableScripts true",
      blocked: false,
    });
  }
}

function createWebviewPanel(viewType, title, showOptions, options) {
  const state = {
    html: "",
    options: Object.assign({}, options || {}),
  };
  record({
    kind: "webview",
    operation: "createPanel",
    target: String(viewType || ""),
    detail: String(title || ""),
    blocked: false,
  });
  recordWebviewOptions(viewType, state.options);

  const webview = {
    cspSource: "vscode-resource://red-widow-sandbox",
    asWebviewUri: (uri) => uri,
    postMessage: async () => false,
    onDidReceiveMessage: (callback) => {
      record({
        kind: "webview",
        operation: "onDidReceiveMessage",
        target: String(viewType || ""),
        detail: typeof callback === "function" ? "handler registered" : "",
        blocked: false,
      });
      return { dispose: () => undefined };
    },
    get html() {
      return state.html;
    },
    set html(value) {
      const html = String(value || "");
      state.html = html;
      const scriptSurface = htmlHasScriptSurface(html, state.options);
      const csp = isStrictWebviewCsp(html);
      record({
        kind: "webview",
        operation: "setHtml",
        target: String(viewType || ""),
        detail: scriptSurface ? (csp ? "strict csp" : "missing csp") : "html assigned",
        canary: hasCanary(html),
        blocked: false,
      });
    },
    get options() {
      return state.options;
    },
    set options(value) {
      state.options = Object.assign({}, value || {});
      recordWebviewOptions(viewType, state.options);
    },
  };

  return {
    viewType: String(viewType || ""),
    title: String(title || ""),
    webview,
    reveal: () => undefined,
    dispose: () => undefined,
    onDidDispose: () => ({ dispose: () => undefined }),
    onDidChangeViewState: () => ({ dispose: () => undefined }),
  };
}

function createTerminal(...args) {
  record({
    kind: "terminal",
    operation: "createTerminal",
    target: commandFromArgs(args.slice(0, 2)),
    blocked: false,
  });
  return {
    name: typeof args[0] === "string" ? args[0] : "red-widow-terminal",
    processId: Promise.resolve(0),
    sendText: (text, addNewLine) => {
      record({
        kind: "terminal",
        operation: "sendText",
        target: String(text || ""),
        detail: addNewLine === false ? "no newline" : "",
        canary: hasCanary(text),
        blocked: true,
      });
    },
    show: () => undefined,
    hide: () => undefined,
    dispose: () => undefined,
  };
}

function vscodeStub() {
  const workspaceFolder = {
    uri: { fsPath: workspaceRoot, path: workspaceRoot, scheme: "file", toString: () => `file://${workspaceRoot}` },
    name: "red-widow-canary-workspace",
    index: 0,
  };
  return {
    Uri: {
      file: (filePath) => ({ fsPath: path.resolve(String(filePath)), path: path.resolve(String(filePath)), scheme: "file", toString: () => `file://${path.resolve(String(filePath))}` }),
    },
    ViewColumn: { Active: -1, Beside: -2, One: 1, Two: 2, Three: 3 },
    workspace: {
      rootPath: workspaceRoot,
      workspaceFolders: [workspaceFolder],
      getConfiguration: () => ({ get: () => undefined, update: async () => undefined }),
      asRelativePath: (filePath) => path.relative(workspaceRoot, pathFor(filePath)),
      fs: {
        readFile: async (uri) => {
          const result = await originalFs.promises.readFile(pathFor(uri));
          recordFs("readFile", pathFor(uri), result, false);
          return result;
        },
        writeFile: async (uri, data) => {
          recordFs("writeFile", pathFor(uri), data, false);
          return originalFs.promises.writeFile(pathFor(uri), data);
        },
        readDirectory: async (uri) => {
          recordFs("readDirectory", pathFor(uri), "", false);
          return originalFs.promises.readdir(pathFor(uri), { withFileTypes: true });
        },
        stat: async (uri) => {
          recordFs("stat", pathFor(uri), "", false);
          return originalFs.promises.stat(pathFor(uri));
        },
      },
    },
    commands: {
      registerCommand: (name, callback) => {
        registeredCommands.push({ name, callback });
        return { dispose: () => undefined };
      },
      executeCommand: async (name, ...args) => {
        const command = registeredCommands.find((item) => item.name === name);
        if (command) {
          return command.callback(...args);
        }
        return undefined;
      },
    },
    window: {
      showInformationMessage: async () => undefined,
      showWarningMessage: async () => undefined,
      showErrorMessage: async () => undefined,
      createOutputChannel: () => ({ appendLine: () => undefined, append: () => undefined, show: () => undefined, dispose: () => undefined }),
      createTerminal,
      createWebviewPanel,
    },
    env: {
      machineId: "red-widow-sandbox",
      appName: "Red Widow Sandbox",
      openExternal: async () => false,
    },
    ExtensionMode: { Production: 1, Development: 2, Test: 3 },
  };
}

function extensionContext() {
  return {
    subscriptions: [],
    extensionPath: extensionRoot,
    extensionUri: { fsPath: extensionRoot, path: extensionRoot, scheme: "file" },
    storagePath: path.join(workspaceRoot, ".red-widow-storage"),
    globalStoragePath: path.join(workspaceRoot, ".red-widow-global-storage"),
    logPath: path.join(workspaceRoot, ".red-widow-logs"),
    workspaceState: { get: () => undefined, update: async () => undefined },
    globalState: { get: () => undefined, update: async () => undefined, setKeysForSync: () => undefined },
    secrets: { get: async () => undefined, store: async () => undefined, delete: async () => undefined },
    asAbsolutePath: (relativePath) => path.join(extensionRoot, relativePath),
  };
}

async function loadExtension(mainPath, manifest) {
  const type = manifest && manifest.type;
  if (mainPath.endsWith(".mjs") || type === "module") {
    return import(url.pathToFileURL(mainPath).href);
  }
  return require(mainPath);
}

async function main() {
  patchFs();
  patchChildProcess();
  patchNetwork();
  process.env.RW_CANARY_TOKEN = marker;
  patchProcessEnv();
  if (typeof Module.syncBuiltinESMExports === "function") {
    Module.syncBuiltinESMExports();
  }
  Module._load = function redWidowModuleLoad(request, parent, isMain) {
    if (request === "vscode") {
      return vscodeStub();
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  process.chdir(workspaceRoot);

  const extension = await loadExtension(path.resolve(config.mainPath), config.manifest || {});
  if (extension && typeof extension.activate === "function") {
    await extension.activate(extensionContext());
  }

  for (const command of registeredCommands) {
    try {
      await command.callback();
    } catch (error) {
      report.errors.push(`command ${command.name}: ${error && error.stack ? error.stack : String(error)}`);
    }
  }
}

main()
  .catch((error) => {
    report.errors.push(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  })
  .finally(() => {
    try {
      originalFs.writeFileSync(config.reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
    } catch (error) {
      console.error(error && error.stack ? error.stack : String(error));
      process.exitCode = 1;
    }
  });
