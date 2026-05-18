# Electronegativity Full Electron Audit Buildout Spec

Status: draft-for-review
Owner: Ghost / Ryushe
Reviewer: pending Codex review
Repo: `https://github.com/ghostonbutterbread/electronegativity`
Branch: `ghost/electron-security-audit-spec`
Canonical planning context:
- `docs/ghost/electron-security-audit-modernization-spec.md`
- `docs/ghost/current-electron-security-gap-analysis.md`
- Ghost workspace spec: `/home/ryushe/.openclaw/workspace/agents/specs/features/2026-05-18-electronegativity-modernization.md`
Last updated: 2026-05-18

## 1. Objective

Expand the Electronegativity fork into a full static Electron audit tool that gives Ghost and Ryushe a reliable first-pass security map for Electron desktop applications.

The tool should be deterministic enough to catch common Electron security-page misconfigurations, but rich enough to produce app-specific security hypotheses for deeper agent and dynamic validation work.

Primary hunt goal for Canva-style apps:

```text
attacker-controlled input -> renderer JavaScript execution -> preload/HostRpc/IPC reachability -> meaningful desktop/app impact
```

The scanner should not prove the full exploit chain by itself. Its job is to map likely trust boundaries, suspicious source/sink/bridge evidence, and hand off precise hypotheses to Electron Team agents.

## 2. Design principles

### 2.1 Deterministic scanner first

Known Electron checklist items should be handled by static checks, not LLM agents. Static tooling gives repeatable findings, diffs, tests, and CI behavior.

### 2.2 Agents consume scanner evidence

Agents should not rediscover baseline config facts. The scanner should emit structured evidence that Electron Team agents can reason over.

### 2.3 Version-aware, not stale-checklist-only

Electron security defaults changed over time. A missing setting may mean different things depending on Electron version. Explicit insecure values are always important; missing values need version-aware interpretation.

### 2.4 Trust-boundary output, not just findings

The scanner should output both:

- `findings`: likely security issues or hardening failures.
- `hypotheses`: source-to-sink-to-bridge paths that need agent tracing or dynamic validation.

### 2.5 Read-only and safe

The scanner must not run the target app, interact with vendor infrastructure, perform CDP actions, mutate files outside its output path, or attempt exploitation.

## 3. System architecture

```text
Input app source / .asar / extracted bundle
        |
        v
Electronegativity scanner
        |
        +--> checklist findings JSON/SARIF
        +--> component inventory JSON
        +--> hypotheses JSONL
        |
        v
Bug bounty harness wrapper: electron_security_audit
        |
        v
Electron Team baseline/hypothesis mode
        |
        +--> focused static agents
        +--> single-agent trace tasks
        +--> dynamic validation candidates
```

### 3.1 Relationship to AppMap

AppMap remains broad, neutral application cartography.

Electronegativity should not replace AppMap. It should add an Electron-specific semantic overlay:

- Which renderer containers exist?
- Which windows load remote or local content?
- Which preload/bridge APIs are exposed?
- Which IPC channels exist?
- Which source/sink/bridge paths look security-relevant?

When AppMap evidence is available, the scanner or harness adapter can attach `appmap_refs` to findings/hypotheses. If AppMap is unavailable, scanner output should still stand alone.

## 4. Input support

### 4.1 Supported targets

- Extracted Electron app directory.
- `.asar` archive.
- Individual JS/TS/HTML/JSON files.
- Future optional package root containing `package.json`, build configs, Electron Forge/Builder config.

### 4.2 Parsing support

Current parser support should be audited and modernized for:

- JavaScript
- TypeScript
- JSX/TSX
- modern class fields/private fields
- optional chaining/nullish coalescing
- ESM imports
- dynamic imports
- minified bundled code best-effort handling

Parser failures must be non-fatal and represented in output.

## 5. Output contract

### 5.1 Output files

The scanner should support an output directory mode that writes:

```text
out/
├── findings.json
├── findings.sarif
├── hypotheses.jsonl
├── inventory.json
├── parse_errors.jsonl
└── summary.md
```

Existing single-file CSV/SARIF behavior should remain compatible when feasible.

### 5.2 Finding schema

Each finding should include:

```json
{
  "type": "finding",
  "check_id": "IPC_SENDER_VALIDATION_MISSING",
  "title": "IPC handler lacks visible sender validation",
  "severity": "medium|high|critical|info",
  "confidence": "tentative|firm|high",
  "file": "relative/path.js",
  "line": 123,
  "column": 4,
  "evidence": "ipcMain.handle('export-file', ...)",
  "electron_component": "main|preload|renderer|protocol|ipc|window|webview",
  "affected_window_or_channel": "export-file",
  "trust_boundary": "renderer_to_main_ipc",
  "version_context": {
    "electron_version": "41.1.0",
    "default_behavior": "sandbox_default_true"
  },
  "manual_review": true,
  "next_agent_hint": "Trace whether untrusted renderer content can invoke this channel."
}
```

### 5.3 Hypothesis schema

Each hypothesis should include:

```json
{
  "type": "hypothesis",
  "hypothesis_id": "ELECTRON-H001",
  "title": "Imported SVG metadata may reach HTML render sink before bridge call",
  "source_label": "file_upload_import",
  "sink_label": "dom_inner_html",
  "bridge_label": "context_bridge_or_hostrpc_unknown",
  "impact_label": "ipc_reachability_unknown",
  "chain": [
    {"kind": "source", "label": "file_upload_import", "file": "...", "line": 10},
    {"kind": "sink", "label": "dom_inner_html", "file": "...", "line": 42},
    {"kind": "bridge", "label": "preload_global", "file": "...", "line": 5}
  ],
  "confidence": "low|medium|high",
  "rank": 0.0,
  "missing_evidence": ["source-to-sink trace", "runtime frame privilege"],
  "next_agent_hint": "Run renderer-js-sink-agent with these files and ask if source reaches sink."
}
```

### 5.4 Inventory schema

Inventory should capture discovered Electron components even when no issue is found:

- windows / renderer containers
- webPreferences values
- preload files
- exposed globals/methods
- IPC channels
- protocol handlers
- navigation/window-open handlers
- permission handlers
- file/protocol usage
- renderer sinks
- suspected content vectors

This inventory becomes the static baseline map for agents.

## 6. Check families and build requirements

## 6.1 Version-aware Electron security defaults

### Problem

The upstream scanner has checks written around older Electron defaults. Current Electron defaults changed:

- `nodeIntegration`: default false since Electron 5.
- `contextIsolation`: default true since Electron 12.
- `sandbox`: default true since Electron 20.

### Requirements

- Detect Electron version from package metadata, Electron binary metadata when available, lockfiles, or explicit CLI flag.
- Model explicit insecure settings as findings regardless of version.
- Model missing settings according to detected version.
- Downgrade or relabel missing secure-by-default settings as `info`/`hardening` instead of high severity.
- Detect interactions where another setting changes effective behavior, especially `nodeIntegration: true` and preload sandbox behavior.

### Deliverables

- `VersionContext` helper.
- Tests for Electron 4, 5, 12, 20, and latest-style behavior.
- Migration of `ContextIsolationJSCheck`, `SandboxJSCheck`, and `NodeIntegrationJSCheck` to version-aware semantics.

## 6.2 Renderer container inventory

### Problem

Existing checks mostly cover `BrowserWindow` and `BrowserView`. Current Electron docs include `WebContentsView`, and real apps may wrap renderer creation in factories.

### Requirements

- Detect `BrowserWindow`, `BrowserView`, `WebContentsView`, and `<webview>` usage.
- Extract `webPreferences` where statically possible.
- Link container to preload, loadURL/loadFile target, session partition, and navigation/window handlers when nearby.
- Output container records to `inventory.json`.

### Deliverables

- Renderer container extractor.
- Component labels in findings.
- Fixtures for direct and factory-created windows.

## 6.3 Preload and exposed API audit

### Problem

The existing `PreloadJSCheck` only flags preload presence. Modern risk is what preload exposes to untrusted renderer code.

### Requirements

- Inventory `contextBridge.exposeInMainWorld` globals and methods.
- Detect direct or indirect exposure of:
  - `ipcRenderer`
  - raw event objects
  - `require`
  - `process`
  - `Buffer`
  - `fs`
  - `path`
  - `shell`
  - `child_process`
- Detect arbitrary IPC forwarding wrappers such as `send(channel, ...args)` or `invoke(channel, payload)`.
- Detect bridge methods that route user-controlled inputs into known dangerous APIs.
- Emit bridge inventory even when no clear issue is found.

### Deliverables

- `PRELOAD_RAW_IPC_EXPOSURE`
- `PRELOAD_ARBITRARY_CHANNEL_FORWARD`
- `PRELOAD_NODE_PRIMITIVE_EXPOSURE`
- `PRELOAD_DANGEROUS_API_WRAPPER`
- Tests for safe allowlisted wrappers vs unsafe generic forwarding.

## 6.4 IPC contract audit

### Problem

Current Electron docs explicitly require validating IPC senders. Upstream lacks a modern first-class `ipcMain` sender-validation audit.

### Requirements

- Inventory channels from:
  - `ipcMain.handle`
  - `ipcMain.handleOnce`
  - `ipcMain.on`
  - `ipcMain.once`
- Identify whether handlers inspect or validate:
  - `event.senderFrame.url`
  - `event.sender.getURL()`
  - `event.senderFrame.origin` where applicable
  - frame/process IDs
  - explicit allowlists
- Tag dangerous sinks inside handlers:
  - filesystem read/write/open
  - `shell.openExternal`, `shell.openPath`, `showItemInFolder`
  - child process/native helper calls
  - custom protocol/deeplink actions
  - auth/session/account actions
  - import/export/file conversion actions
- Flag dangerous handlers with no visible sender validation.
- Link preload arbitrary forwarding to matching main-process channels when possible.

### Deliverables

- `IPC_CHANNEL_INVENTORY`
- `IPC_SENDER_VALIDATION_MISSING`
- `IPC_DANGEROUS_SINK_NO_SENDER_VALIDATION`
- `IPC_ARBITRARY_FORWARDING_TO_DANGEROUS_CHANNEL`
- Tests for sender-validated and unvalidated handlers.

## 6.5 Navigation, window-open, and external-open audit

### Problem

Current checks detect handler presence but not allowlist quality.

### Requirements

- Detect `will-navigate`, `setWindowOpenHandler`, legacy `new-window`, and `web-contents-created` patterns.
- Analyze whether code denies by default.
- Flag allow-all returns such as `{ action: 'allow' }` without validation.
- Detect whether `new URL()` parsing and host/protocol allowlists are present.
- Track `shell.openExternal` usage inside window-open/navigation logic.
- Distinguish constant URLs from variable/user-controlled URLs.

### Deliverables

- `NAVIGATION_ALLOW_ALL`
- `WINDOW_OPEN_ALLOW_ALL`
- `OPEN_EXTERNAL_UNVALIDATED_URL`
- `OPEN_EXTERNAL_IN_WINDOW_HANDLER_UNVALIDATED`
- Tests for deny-by-default allowlist patterns.

## 6.6 Custom protocol and file protocol audit

### Problem

Current docs recommend avoiding `file://` and using custom protocols. Existing protocol detection misses `protocol.handle` and does not inspect privilege flags.

### Requirements

- Detect `loadFile`, `loadURL('file://...')`, file URLs in HTML, and file-scheme custom routing.
- Detect modern protocol APIs:
  - `protocol.handle`
  - `protocol.registerSchemesAsPrivileged`
- Detect older APIs for compatibility:
  - `registerFileProtocol`, `registerBufferProtocol`, etc.
- Inventory custom scheme privileges:
  - `standard`
  - `secure`
  - `supportFetchAPI`
  - `corsEnabled`
  - `stream`
  - `bypassCSP`
  - `allowServiceWorkers`
- Flag risky mappings from URL path/input to local filesystem without normalization/allowlist.

### Deliverables

- `FILE_PROTOCOL_APP_CONTENT`
- `CUSTOM_PROTOCOL_BYPASS_CSP`
- `CUSTOM_PROTOCOL_FILE_PATH_TRAVERSAL_RISK`
- `CUSTOM_PROTOCOL_MISSING_SECURE_STANDARD_FLAGS`
- Tests for `protocol.handle` and privilege configurations.

## 6.7 Electron fuses audit

### Problem

Electron's current security docs include fuses. Upstream does not appear to check them.

### Requirements

- Detect fuse configuration from build tooling where possible.
- Support explicit metadata input for packaged apps if static config is unavailable.
- Emit hardening recommendations for risky or unset fuses:
  - `RunAsNode`
  - `EnableNodeCliInspectArguments`
  - `EnableEmbeddedAsarIntegrityValidation`
  - `OnlyLoadAppFromAsar`
  - other current fuse options after docs review.

### Deliverables

- `FUSE_RUN_AS_NODE_ENABLED_OR_UNKNOWN`
- `FUSE_NODE_CLI_INSPECT_ENABLED_OR_UNKNOWN`
- `FUSE_ASAR_INTEGRITY_NOT_ENABLED`
- `FUSE_ONLY_LOAD_APP_FROM_ASAR_NOT_ENABLED`
- Tests with sample fuse configs.

## 6.8 Permission handler quality

### Problem

Existing checks detect presence of `setPermissionRequestHandler`, but current risk depends on whether the handler validates origin/session/permission and denies by default.

### Requirements

- Detect remote-content sessions without permission handlers.
- Analyze handler quality:
  - `callback(true)` broad grants
  - missing URL/origin parsing
  - missing permission allowlist
  - grants for sensitive permissions such as media, geolocation, notifications, clipboard, display-capture, midi, etc.
- Track `session.defaultSession` and partitioned sessions.

### Deliverables

- `PERMISSION_HANDLER_MISSING_FOR_REMOTE_CONTENT`
- `PERMISSION_HANDLER_ALLOW_ALL`
- `PERMISSION_HANDLER_NO_ORIGIN_CHECK`
- Tests for safe and unsafe handlers.

## 6.9 CSP quality audit

### Problem

CSP existence is not enough for XSS-to-bridge risk analysis.

### Requirements

- Parse CSP from meta tags and Electron-injected headers where statically visible.
- Flag dangerous directives:
  - `unsafe-inline`
  - `unsafe-eval`
  - wildcard script sources
  - broad `default-src *`
  - missing `object-src 'none'`
  - overly broad `frame-src` and `connect-src`
- Label whether the CSP meaningfully reduces renderer JS execution risk.

### Deliverables

- `CSP_UNSAFE_INLINE`
- `CSP_UNSAFE_EVAL`
- `CSP_SCRIPT_SRC_WILDCARD`
- `CSP_WEAK_FOR_RENDERER_XSS`
- Tests with HTML and header-injection examples.

## 6.10 Renderer JavaScript sink and content-vector mapper

### Problem

Generic Electron checklist scanning does not map app-specific renderer JS execution opportunities. This is central to Canva-style hunting.

### Requirements

- Inventory high-risk JS execution/render sinks:
  - `innerHTML`
  - `outerHTML`
  - `insertAdjacentHTML`
  - `DOMParser.parseFromString`
  - `Range.createContextualFragment`
  - `iframe.srcdoc`
  - dynamic script creation
  - `eval`
  - `Function`
  - string timers
  - markdown/rich-text/HTML renderer wrappers
  - sanitizer calls and sanitizer bypass-prone options
- Add heuristic source labels based on nearby code, filenames, symbols, and imports:
  - file upload/import
  - export/preview
  - pasted content
  - comments/collaboration
  - templates/assets
  - AI-generated or AI-consumed content
  - deeplink/custom protocol input
- Output hypotheses when a likely untrusted source and execution sink are near or linkable.

### Deliverables

- `RENDERER_HTML_SINK_INVENTORY`
- `RENDERER_POTENTIAL_XSS_SINK`
- `RENDERER_SANITIZER_WEAK_OR_UNKNOWN`
- `CONTENT_VECTOR_LABEL`
- Hypotheses JSONL entries for source/sink candidates.
- Tests using fixture renderers.

## 6.11 Hypothesis ranking

### Requirements

Rank hypotheses higher when they have:

- attacker-controlled source labels,
- known dangerous renderer sinks,
- weak CSP/sanitization,
- same-frame/top-frame execution likelihood,
- nearby preload/global bridge evidence,
- matching IPC channels with dangerous sinks,
- desktop-specific impact labels.

Rank lower when:

- source is local/trusted only,
- sink is isolated in sandboxed iframe,
- strong sanitizer/CSP evidence exists,
- bridge reachability is absent or explicitly blocked.

### Deliverables

- Ranking function with transparent scoring fields.
- Tests for obvious high/low ranking cases.

## 7. CLI design

Existing CLI should remain compatible, but add a modern output mode:

```bash
electronegativity audit \
  --input /path/to/app.asar-or-dir \
  --electron-version 41.1.0 \
  --output-dir ./audit-out \
  --format json,sarif,hypotheses \
  --profile full
```

Profiles:

- `checklist`: deterministic Electron security checklist only.
- `trust-map`: inventory + trust-boundary/hypothesis output.
- `full`: checklist + trust-map.
- `canva-like`: optional future profile that emphasizes collaboration, file import/export, AI, and template/content vectors.

If changing CLI shape is too invasive for MVP, add flags to existing CLI first and defer subcommands.

## 8. Test strategy

### 8.1 Baseline tests

- Run existing upstream tests before modifications.
- Record current failures separately from new failures.

### 8.2 Fixture apps

Create small fixture apps for:

- old Electron defaults vs modern defaults,
- safe vs unsafe preload exposure,
- safe vs unsafe IPC handlers,
- safe vs unsafe navigation/window-open handlers,
- custom protocol safe/unsafe mapping,
- CSP quality cases,
- renderer source/sink/content-vector examples.

### 8.3 Snapshot output tests

For each fixture, assert:

- expected finding IDs,
- expected inventory records,
- expected hypothesis count/ranking,
- no false positive on safe counterexamples.

## 9. Implementation phases

### Phase 0 — Baseline health

- Run `npm install`/build/test in the fork.
- Record dependency/toolchain breakages.
- Add this spec and gap analysis as docs.

Exit criteria:

- Known baseline test result is recorded.
- No implementation begins before baseline is understood.

### Phase 1 — Schema and output foundation

- Add stable finding/inventory/hypothesis schemas.
- Add output directory writer.
- Preserve existing output compatibility.

Exit criteria:

- Existing checks can emit new schema.
- Tests cover output format.

### Phase 2 — Version-aware defaults and renderer inventory

- Add `VersionContext`.
- Update node/context/sandbox checks.
- Add renderer container inventory including `WebContentsView`.

Exit criteria:

- Version-specific fixtures pass.
- Inventory lists renderer containers and webPreferences.

### Phase 3 — Preload and IPC audit

- Add preload exposure checks.
- Add IPC inventory and sender validation checks.
- Link preload forwarding to IPC handlers when possible.

Exit criteria:

- Safe/unsafe preload and IPC fixtures pass.
- Hypotheses include bridge/IPC labels.

### Phase 4 — Navigation, protocol, permission, CSP quality

- Improve navigation/window-open/openExternal checks.
- Add custom protocol/file protocol checks.
- Add fuse checks.
- Improve permission and CSP quality checks.

Exit criteria:

- Checklist current-doc parity is substantially complete.

### Phase 5 — Renderer JS sink and content-vector mapper

- Add renderer sink inventory.
- Add source-vector labels.
- Add source/sink hypotheses.

Exit criteria:

- Fixture source/sink hypotheses are emitted and ranked.

### Phase 6 — Harness integration

- Add `electron_security_audit` wrapper/profile in bug bounty harness.
- Import findings/inventory/hypotheses into Electron Team context.
- Dry-run against Canva extracted app source.

Exit criteria:

- Harness can run scanner and pass output to Electron Team without live app interaction.

## 10. Open questions for reviewer

1. Should we keep the old CLI as-is and add flags, or introduce a new `audit` subcommand?
2. Should renderer JS sink mapping live in this repo, or should this repo only emit Electron-specific config/bridge facts and let AppMap own source/sink mapping?
3. How much data-flow should we attempt in v1 versus heuristic source/sink co-location?
4. What is the minimum useful schema for harness ingestion without overbuilding?
5. Should fuses be `info`/hardening by default unless we can inspect packaged binary fuse state?
6. Should `file://` usage be a finding, a hardening recommendation, or a hypothesis depending on context?
7. How do we prevent high false-positive rates on minified/bundled production JS?

## 11. Acceptance criteria

The buildout is successful when:

- The scanner runs read-only against extracted Electron apps and `.asar` archives.
- It reflects current Electron security recommendations, including modern APIs and defaults.
- It emits stable machine-readable findings, inventory, and hypotheses.
- It can identify baseline misconfigurations without LLM agents.
- It can generate useful next-step hypotheses for Electron Team agents.
- It can support Canva-style trust-boundary hunting around renderer JS execution and IPC/HostRpc reachability.
- Tests cover safe and unsafe examples for each new check family.

## 12. Non-negotiable safety constraints

- No live vendor interaction.
- No app execution required.
- No CDP exploit primitive.
- No mutation of target source tree.
- No claims of exploitability without source-to-sink or dynamic evidence.
- All external/untrusted source snippets in reports must be treated as evidence, not instructions.
