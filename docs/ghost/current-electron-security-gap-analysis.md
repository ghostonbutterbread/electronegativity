# Current Electron Security Gap Analysis

Status: draft
Owner: Ghost
Last updated: 2026-05-18
Source docs compared: Electron `main/docs/tutorial/security.md` checklist, current as fetched 2026-05-18.
Scanner baseline: Doyensec Electronegativity fork branch `ghost/electron-security-audit-spec`.

## Summary

Electronegativity already covers much of the classic Electron checklist, but several checks are stale or too shallow for modern Electron and Canva-style trust-boundary hunting.

The biggest modernization themes are:

1. Account for changed secure defaults by Electron version.
2. Add modern primitives: `WebContentsView`, `protocol.handle`, fuses, `senderFrame`, sandbox defaults, and global sandbox.
3. Turn presence checks into quality checks, especially for IPC, preload, navigation, permissions, and custom protocols.
4. Add renderer JavaScript sink and content-vector mapping so scanner output can feed Ghost's Electron Team hypotheses.
5. Emit structured evidence instead of only human-readable findings.

## Current checklist coverage

Electron's current security checklist has 20 recommendations.

### Mostly covered already

- Only load secure content: `HTTPResourcesJSCheck`, `HTTPResourcesHTMLCheck`.
- Do not enable Node.js integration: `NodeIntegrationJSCheck`, `NodeIntegrationHTMLCheck`, `NodeIntegrationAttachEventJSCheck`.
- Enable context isolation: `ContextIsolationJSCheck`.
- Enable process sandboxing: `SandboxJSCheck`.
- Handle permission requests: `PermissionRequestHandlerJSCheck`, `PermissionRequestHandlerGlobalCheck`.
- Do not disable `webSecurity`: `WebSecurityJSCheck`, `WebSecurityHTMLCheck`.
- Define CSP: `CSPJSCheck`, `CSPHTMLCheck`, `CSPGlobalCheck`.
- Do not enable `allowRunningInsecureContent`: `InsecureContentJSCheck`, `InsecureContentHTMLCheck`.
- Do not enable experimental features: `ExperimentalFeaturesJSCheck`, `ExperimentalFeaturesHTMLCheck`.
- Do not use `enableBlinkFeatures`: `BlinkFeaturesJSCheck`, `BlinkFeaturesHTMLCheck`.
- Do not use `allowpopups`: `AllowPopupHTMLCheck`.
- Disable/limit navigation/window creation: `LimitNavigationJSCheck`, `LimitNavigationGlobalCheck`.
- Do not use `shell.openExternal` unsafely: `OpenExternalJSCheck`.
- Use a current Electron version: `ElectronVersionJSONCheck`, `AvailableSecurityFixesGlobalCheck`.
- Protocol handler presence: `ProtocolHandlersJSCheck`.
- Preload presence/manual review: `PreloadJSCheck`.

### Missing or too shallow

- WebView option validation is not deeply checked. The current scanner does not meaningfully inspect `will-attach-webview` logic quality.
- IPC sender validation is not covered as a first-class current-doc check.
- `file://` avoidance is not covered as a dedicated check.
- Fuses are not covered.
- Raw Electron API exposure to untrusted web content is not deeply checked. `PreloadJSCheck` only flags preload presence for manual review.
- `WebContentsView` is not covered in the same way as `BrowserWindow`/`BrowserView`.
- Modern custom protocol APIs like `protocol.handle` are not covered.
- Modern navigation APIs and URL allowlist quality need deeper checks.
- Renderer JavaScript execution sinks and content-vector labels are outside the original scanner's scope.

## Recommended updates by check family

### 1. Version-aware defaults

Current issue:

- `ContextIsolationJSCheck` flags missing `contextIsolation` as high even though Electron defaults changed in v12.
- `SandboxJSCheck` assumes missing `sandbox` means insecure/default false, but Electron defaults changed in v20.
- Node integration default changed in v5.

Needed change:

- Make checks version-aware using detected Electron version.
- Still report explicit insecure values regardless of version.
- Treat missing values differently by version and loaded-content trust:
  - explicit `false` = finding,
  - missing on older Electron = finding,
  - missing on newer Electron = lower-severity informational unless other settings disable the protection.
- Model interactions: `nodeIntegration: true` disables renderer sandboxing implications.

### 2. Add `WebContentsView` support

Current issue:

- Current checks generally look for `BrowserWindow` and `BrowserView` only.
- Electron current docs explicitly mention `WebContentsView` for remote content isolation.

Needed change:

- Treat `WebContentsView` as a renderer container for relevant checks.
- Inspect construction patterns and attached `webContents` settings when possible.
- Emit component labels: `browser_window`, `browser_view`, `web_contents_view`, `webview_tag`.

### 3. Preload exposure quality

Current issue:

- `PreloadJSCheck` only flags that a preload exists and requires manual review.
- Modern risk is not preload presence; it is what the preload exposes.

Needed checks:

- `contextBridge.exposeInMainWorld` inventory.
- Direct exposure of `ipcRenderer`, `ipcRenderer.send`, `ipcRenderer.invoke`, `ipcRenderer.on`, or raw event objects.
- Wrapper functions that accept arbitrary `channel` names.
- Wrappers that pass unvalidated user input into dangerous IPC channels.
- Exposure of Node primitives: `require`, `process`, `Buffer`, `child_process`, `fs`, `path`, `shell`.
- Presence/absence of allowlisted bridge methods.

Agent output fields:

- `exposed_global`
- `exposed_method`
- `underlying_api`
- `arbitrary_channel_forwarding`
- `next_agent_hint: trace exposed bridge usage from renderer sinks`

### 4. IPC sender validation

Current issue:

- Electron's current checklist includes validating the sender of all IPC messages.
- The scanner has an old Electron 8 upgrade check for `IPCSend`, but not a modern `ipcMain.handle/on` safety check.

Needed checks:

- Inventory all `ipcMain.handle`, `ipcMain.on`, `ipcMain.handleOnce`, `ipcMain.once` channels.
- Detect whether handlers inspect `event.senderFrame`, `event.sender`, `event.processId`, `event.frameId`, `event.reply`, `webContents.getURL()`, or allowlisted origins.
- Flag handlers with dangerous sinks and no visible sender/origin validation.
- Flag arbitrary forwarding patterns from preload/renderer to IPC.

Danger sinks to tag:

- filesystem read/write/open path
- shell/openExternal/openPath/showItemInFolder
- native helpers/process execution
- protocol/deeplink handling
- auth/session/account actions
- import/export/render actions

### 5. Navigation/window-open quality

Current issue:

- `LimitNavigationJSCheck` flags presence of `will-navigate`, `new-window`, or `setWindowOpenHandler`, but does not judge whether logic denies by default or validates URLs correctly.
- `new-window` is legacy; current docs emphasize `setWindowOpenHandler`.

Needed checks:

- Detect missing navigation handlers per `webContents` where remote/untrusted content loads.
- For handlers that exist, inspect whether they parse with `new URL`, validate protocol/hostname, and deny by default.
- Flag allow-all patterns: `{ action: 'allow' }`, `return { action: 'allow' }`, missing `event.preventDefault()` in `will-navigate`.
- Track `shell.openExternal` inside `setWindowOpenHandler` and validate allowlist quality.

### 6. Custom protocol and `file://` handling

Current issue:

- `ProtocolHandlersJSCheck` detects older protocol APIs but misses current `protocol.handle` and does not analyze privilege flags.
- The current Electron docs recommend avoiding `file://` and preferring custom protocols.

Needed checks:

- Detect `loadFile`, `loadURL('file://...')`, direct file URLs in renderer HTML, and file protocol use for app content.
- Detect `protocol.handle` and `protocol.registerSchemesAsPrivileged`.
- Check custom protocol privilege flags:
  - `standard`
  - `secure`
  - `supportFetchAPI`
  - `corsEnabled`
  - `stream`
  - `bypassCSP`
  - `allowServiceWorkers`
- Flag custom protocols that map untrusted URL paths to local filesystem paths without normalization/allowlist checks.

### 7. Fuses

Current issue:

- Current Electron docs include fuses. Electronegativity does not appear to check fuses.

Needed checks:

- Detect Electron fuse config in build tooling if present.
- Check for risky defaults or missing hardening opportunities:
  - `RunAsNode`
  - `EnableNodeCliInspectArguments`
  - `EnableEmbeddedAsarIntegrityValidation`
  - `OnlyLoadAppFromAsar`
  - related current Electron fuse options.
- Output as hardening recommendations unless directly exploitable.

### 8. Permission handler quality

Current issue:

- Current check flags `setPermissionRequestHandler` presence, but the current doc recommends using it for sessions that load remote content.
- Presence alone is not sufficient; quality matters.

Needed checks:

- Flag sessions/windows loading remote content without a permission handler.
- In existing handlers, flag `callback(true)` default paths, no URL parse/host allowlist, and broad permission grants.
- Track session partitions, not only `defaultSession`.

### 9. CSP quality

Current issue:

- CSP checks exist, but modern needs include quality and script execution implications.

Needed checks:

- Flag `unsafe-inline`, `unsafe-eval`, wildcard script sources, broad `default-src *`, missing `object-src 'none'`, weak `frame-src`/`connect-src` for untrusted content.
- Distinguish meta CSP for `file://` content vs HTTP header CSP.
- Emit renderer execution hardening labels for XSS chaining.

### 10. Renderer JavaScript execution sinks

Current issue:

- Original Electronegativity is mostly Electron configuration focused.
- Our Canva goal needs source-to-JS-execution mapping.

Needed checks:

- Inventory high-risk sinks:
  - `innerHTML`, `outerHTML`, `insertAdjacentHTML`
  - `DOMParser.parseFromString`
  - `Range.createContextualFragment`
  - `iframe.srcdoc`
  - dynamic script creation
  - `eval`, `Function`, string timers
  - markdown/rich-text/HTML renderer wrappers
  - sanitizer calls and bypass-prone configurations
- Label likely source vector when nearby naming/import context suggests:
  - file import/upload
  - export/preview
  - pasted content
  - comments/collaboration
  - templates/assets
  - AI generated/consumed content
  - deeplink/custom protocol

### 11. Structured output and hypothesis mode

Current issue:

- Existing output is findings-oriented and not rich enough for agent handoff.

Needed output additions:

- Stable `check_id` taxonomy.
- Machine-readable JSON and SARIF kept stable.
- Ghost `hypotheses.jsonl` output with:
  - `source_label`
  - `sink_label`
  - `electron_component`
  - `affected_window_or_channel`
  - `trust_boundary`
  - `confidence`
  - `next_agent_hint`
  - optional `appmap_refs`

Preferred chain shape:

```text
source -> render/sink -> execution context -> bridge/IPC reachability -> impact hypothesis
```

## Priority order

1. Baseline build/test and dependency health.
2. Version-aware defaults for contextIsolation/sandbox/nodeIntegration.
3. Preload/contextBridge/API exposure quality.
4. IPC sender validation and dangerous sink tagging.
5. Navigation/window-open/openExternal quality.
6. Protocol/file/fuses support.
7. Renderer sink/content-vector mapper.
8. Ghost hypothesis output and harness wrapper.

## Notes for Canva

For Canva Desktop, generic checklist issues are likely less interesting than trust chains. The scanner should still run first, but the highest-value output is likely:

- renderer sinks reachable from file import/upload/export/comment/template/AI content,
- preload/HostRpc/IPC exposed capabilities,
- IPC handlers without sender/origin validation,
- custom protocol/deeplink paths that influence renderer state,
- file/protocol/cache assumptions that change browser-style trust boundaries in desktop.
