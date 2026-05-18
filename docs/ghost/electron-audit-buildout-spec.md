# Electronegativity Full Electron Audit Buildout Spec

Status: reviewed-draft
Owner: Ghost / Ryushe
Reviewer: Codex CLI review completed 2026-05-18
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

The scanner should not prove the full exploit chain by itself. Its job is to map likely trust boundaries, suspicious source/sink/bridge evidence, and hand off precise hypotheses to Electron Team agents. In v1, source-to-sink output is a `candidate_chain` with explicit `missing_evidence`; confirmed reachability requires AppMap support, agent trace, or separately approved dynamic validation.

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

### 2.6 V1 scope boundary

V1 should not become a general static taint engine. Keep the core implementation to deterministic Electron facts, local AST patterns, and shallow/co-located hypotheses. Deep reachability is delegated to AppMap, Electron Team agents, or later explicit data-flow work.

### 2.7 Severity and confidence policy

- `severity` describes likely impact in context. Remote/untrusted content, preload bridge reachability, dangerous IPC sinks, and permissive navigation raise severity. Local-only privileged UI, admin-only surfaces, strong sandboxing, and no bridge evidence lower severity.
- `confidence` describes evidence quality. Literal Electron API misuse with direct location evidence is high confidence; bundled/minified heuristic matches are low confidence unless supported by multiple signals.
- Inventory records should not abuse `severity`. Use `classification` to distinguish `finding`, `hardening`, `inventory`, and `hypothesis`.

### 2.8 False-positive policy for bundled/minified apps

Large production Electron apps often contain minified bundles, generated files, vendored dependencies, and sourcemap gaps. The scanner must classify files before assigning strong findings.

Rules:

- Minified/generated/vendor files default to `inventory` or low-confidence `hypothesis` unless a strong literal Electron API misuse is visible.
- Findings should include `is_minified`, `is_bundle`, `vendor_or_generated`, `source_map_available`, `parser_status`, and optional `suppression_reason`.
- Hypotheses should include `confidence_reasons` and `negative_evidence`, especially when strong CSP, sanitizer evidence, sandboxed iframes, or absent bridge evidence reduces risk.

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

The scanner must not depend on AppMap. It should emit stable `entity_id` and `relationship_id` values for Electron facts and local relationships. The harness/AppMap adapter resolves those IDs into `appmap_refs` when AppMap evidence exists. If AppMap is unavailable, scanner output should still stand alone.

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

Parser failures must be non-fatal and represented in output. Parser modernization and file classification are early-phase prerequisites before broad heuristic sink checks.

## 5. Output contract

### 5.1 Output files

The scanner should support an output directory mode that writes top-level run metadata and result files:

```text
out/
├── run.json
├── findings.json
├── findings.sarif
├── hypotheses.jsonl
├── inventory.json
├── parse_errors.jsonl
└── summary.md
```

Existing single-file CSV/SARIF behavior should remain compatible when feasible.

`run.json` should include:

```json
{
  "schema_version": "1.0",
  "scanner_version": "...",
  "target_id": "stable-or-user-supplied-target-id",
  "input_kind": "asar|directory|file|package_root",
  "electron_version": "41.1.0",
  "electron_version_source": "cli|package_json|lockfile|binary_metadata|unknown",
  "electron_version_confidence": "low|medium|high",
  "generated_at": "ISO-8601 timestamp"
}
```

### 5.2 Finding schema

Each finding should include:

```json
{
  "type": "finding",
  "classification": "finding",
  "check_id": "IPC_SENDER_VALIDATION_MISSING",
  "result_id": "stable hash of check_id + normalized file + location + evidence",
  "title": "IPC handler lacks visible sender validation",
  "severity": "medium|high|critical|info",
  "confidence": "low|medium|high",
  "confidence_reasons": ["dangerous IPC sink", "no visible origin allowlist"],
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
  "validation_state": "static_only",
  "manual_review": true,
  "file_classification": {
    "is_minified": false,
    "is_bundle": false,
    "vendor_or_generated": false,
    "source_map_available": false,
    "parser_status": "ok"
  },
  "next_agent_hint": "Trace whether untrusted renderer content can invoke this channel."
}
```

### 5.3 Hypothesis schema

Each hypothesis should include:

```json
{
  "type": "hypothesis",
  "classification": "hypothesis",
  "hypothesis_id": "stable hash of candidate_chain + evidence",
  "title": "Imported SVG metadata may reach HTML render sink before bridge call",
  "source_label": "file_upload_import",
  "sink_label": "dom_inner_html",
  "bridge_label": "context_bridge_or_hostrpc_unknown",
  "impact_label": "ipc_reachability_unknown",
  "candidate_chain": [
    {"kind": "source", "label": "file_upload_import", "file": "...", "line": 10},
    {"kind": "sink", "label": "dom_inner_html", "file": "...", "line": 42},
    {"kind": "bridge", "label": "preload_global", "file": "...", "line": 5}
  ],
  "confidence": "low|medium|high",
  "confidence_reasons": ["nearby source/sink labels", "preload global present"],
  "negative_evidence": ["no proven source-to-sink trace"],
  "rank": 0.0,
  "validation_state": "static_only",
  "missing_evidence": ["source-to-sink trace", "runtime frame privilege"],
  "next_agent_hint": "Run renderer-js-sink-agent with these files and ask if source reaches sink."
}
```

### 5.4 Inventory schema

Inventory should capture discovered Electron components even when no issue is found:

- run metadata and version/fuse provenance
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
- stable `entity_id` / `relationship_id` values for harness/AppMap resolution

This inventory becomes the static baseline map for agents.

## 6. Check families and build requirements

## 6.1 Version-aware Electron security defaults

### Problem

The upstream scanner has checks written around older Electron defaults. Current Electron defaults changed:

- `nodeIntegration`: default false since Electron 5.
- `contextIsolation`: default true since Electron 12.
- `sandbox`: default true since Electron 20.

### Requirements

- Detect Electron version from package metadata, Electron binary metadata when available, lockfiles, or explicit CLI flag. Always record `electron_version_source` and `electron_version_confidence`.
- Model explicit insecure settings as findings regardless of version, but set severity from content trust and reachability context rather than the setting alone.
- Model missing settings according to detected version.
- Downgrade or relabel missing secure-by-default settings as `info`/`hardening` instead of high severity. Unknown Electron versions should be conservative without pretending precision.
- Detect interactions where another setting changes effective behavior, especially `nodeIntegration: true`, global sandboxing, preload sandbox behavior, `nodeIntegrationInWorker`, and `nodeIntegrationInSubFrames`.

### Deliverables

- `VersionContext` helper.
- Tests for Electron 4, 5, 12, 20, and latest-style behavior.
- Migration of `ContextIsolationJSCheck`, `SandboxJSCheck`, and `NodeIntegrationJSCheck` to version-aware semantics.

## 6.2 Renderer container inventory

### Problem

Existing checks mostly cover `BrowserWindow` and `BrowserView`. Current Electron docs include `WebContentsView`, and real apps may wrap renderer creation in factories.

### Requirements

- Detect `BrowserWindow`, `BrowserView`, `WebContentsView`, and `<webview>` usage, including `will-attach-webview` handlers.
- Extract `webPreferences` where statically possible.
- Link container to preload, loadURL/loadFile target, session partition, navigation/window handlers, and global sandbox state when nearby.
- Output container records to `inventory.json`.

### Deliverables

- Renderer container extractor.
- `WEBVIEW_WILL_ATTACH_MISSING_OR_WEAK`
- `WEBVIEW_PRELOAD_NOT_STRIPPED_OR_VALIDATED`
- `WEBVIEW_OPTIONS_ALLOW_INSECURE_FEATURES`
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
  - explicit URL/origin/frame allowlists
  - frame/process IDs as weak/inventory evidence only

- Do not count `processId`, `frameId`, or mere `sender` inspection as validation unless tied to URL/origin/frame allowlist logic.
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

- Detect `loadFile`, `loadURL('file://...')`, file URLs in HTML, file-scheme custom routing, and fuse state that changes file protocol privileges.
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
- Flag risky mappings from URL path/input to local filesystem without normalization/allowlist. Treat ordinary `loadFile` as inventory/hardening unless paired with untrusted navigation, permissive file privileges, mixed origins, or path-influenced loads.

### Deliverables

- `FILE_PROTOCOL_APP_CONTENT_INVENTORY`
- `CUSTOM_PROTOCOL_BYPASS_CSP`
- `CUSTOM_PROTOCOL_FILE_PATH_TRAVERSAL_RISK`
- `CUSTOM_PROTOCOL_RISKY_PRIVILEGE_COMBINATION`
- `CUSTOM_PROTOCOL_MISSING_SECURE_STANDARD_FLAGS` only when context requires those flags
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
  - `EnableNodeOptionsEnvironmentVariable`
  - `EnableCookieEncryption`
  - `LoadBrowserProcessSpecificV8Snapshot`
  - `GrantFileProtocolExtraPrivileges`
  - `WasmTrapHandlers`
  - other current fuse options after docs review.

### Deliverables

- `FUSE_RUN_AS_NODE_ENABLED_OR_UNKNOWN`
- `FUSE_NODE_CLI_INSPECT_ENABLED_OR_UNKNOWN`
- `FUSE_ASAR_INTEGRITY_NOT_ENABLED`
- `FUSE_ONLY_LOAD_APP_FROM_ASAR_NOT_ENABLED`
- `FUSE_NODE_OPTIONS_ENV_ENABLED_OR_UNKNOWN`
- `FUSE_GRANT_FILE_PROTOCOL_EXTRA_PRIVILEGES_ENABLED_OR_UNKNOWN`
- `FUSE_COOKIE_ENCRYPTION_DISABLED_OR_UNKNOWN`
- Tests with sample fuse configs and unknown-fuse-state behavior.

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
  - variable-controlled `import()` / script URL construction
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
- Output hypotheses when a likely untrusted source and execution sink are near or linkable. In v1 this is a shallow candidate, not a reachability claim.

### Deliverables

- `RENDERER_HTML_SINK_INVENTORY`
- `RENDERER_POTENTIAL_XSS_SINK`
- `RENDERER_SANITIZER_WEAK_OR_UNKNOWN`
- `CONTENT_VECTOR_LABEL`
- Hypotheses JSONL entries for source/sink candidates using `candidate_chain` and `missing_evidence`.
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

Existing CLI should remain compatible. For MVP, prefer adding flags to the existing CLI rather than introducing a new subcommand. The future shape may become:

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

The `audit` subcommand is explicitly non-MVP unless implementation proves cheap. MVP should add `--output-dir`, `--profile`, `--electron-version`, and structured output flags to the current command path first.

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

### Phase 1 — Parser modernization and file classification

- Audit parser support for modern JS/TS/JSX/TSX.
- Add minified/bundle/vendor/generated detection.
- Make parser failures non-fatal and visible in `parse_errors.jsonl`.

Exit criteria:

- Large bundled apps can be scanned without fatal parser failure.
- File classification fields are available to all checks.

### Phase 2 — Schema v1 and output foundation

- Add stable finding/inventory/hypothesis schemas.
- Add deterministic IDs from `check_id + normalized file + location + evidence hash`.
- Add output directory writer and SARIF mapping.
- Define Electron Team context packet contract early, even if the harness wrapper lands later.
- Preserve existing output compatibility.

Exit criteria:

- Existing checks can emit new schema.
- Tests cover output format and stable IDs.

### Phase 3 — Version and fuse context

- Add `VersionContext` with provenance/confidence.
- Add fuse context with known/unknown state handling.
- Update node/context/sandbox checks for version-aware behavior.

Exit criteria:

- Version-specific fixtures pass.
- Unknown version/fuse state is represented without fake precision.

### Phase 4 — Renderer container/component graph inventory

- Add renderer container inventory including `WebContentsView` and `<webview>`.
- Add `will-attach-webview` inventory/quality checks.
- Link containers to preload, load targets, sessions, navigation handlers, webPreferences, and global sandbox state where statically possible.

Exit criteria:

- Inventory lists renderer containers and webPreferences.
- Webview security controls are represented.

### Phase 5 — Modernize existing checklist checks

- Port existing checks to schema v1 and component graph.
- Reclassify noisy checks into finding/hardening/inventory as appropriate.
- Keep checklist parity deterministic before adding broad hypothesis logic.

Exit criteria:

- Current-doc checklist coverage is substantially complete for existing check families.

### Phase 6 — Preload and IPC audit

- Add preload exposure checks.
- Add IPC inventory and sender validation checks.
- Link preload forwarding to IPC handlers when possible.

Exit criteria:

- Safe/unsafe preload and IPC fixtures pass.
- Hypotheses include bridge/IPC labels without claiming reachability.

### Phase 7 — Navigation, webview, protocol, permission, CSP quality

- Improve navigation/window-open/openExternal checks.
- Add custom protocol/file protocol checks.
- Add permission and CSP quality checks.

Exit criteria:

- Quality checks distinguish safe allowlist patterns from allow-all behavior.

### Phase 8 — Shallow renderer JS sink and content-vector mapper

- Add renderer sink inventory.
- Add source-vector labels.
- Add shallow source/sink candidate hypotheses.

Exit criteria:

- Fixture source/sink hypotheses are emitted and ranked with `candidate_chain`, `missing_evidence`, and negative evidence.

### Phase 9 — Harness integration and large-app tuning

- Add `electron_security_audit` wrapper/profile in bug bounty harness.
- Import findings/inventory/hypotheses into Electron Team context.
- Dry-run against Canva extracted app source and tune suppressions/ranking.

Exit criteria:

- Harness can run scanner and pass output to Electron Team without live app interaction.
- Large bundled app scan produces useful signal without overwhelming false positives.

## 10. Review resolution notes

Codex review completed on 2026-05-18. Accepted changes:

- Added version provenance/confidence and unknown-version behavior.
- Added severity/confidence policy and classification separation.
- Added false-positive policy for minified/bundled/vendor code.
- Re-scoped renderer sink mapping to shallow candidate hypotheses, not data-flow proof.
- Clarified AppMap ownership: scanner emits entity/relationship IDs; harness resolves AppMap refs.
- Added webview `will-attach-webview` checks.
- Expanded fuse coverage with current Electron fuse names.
- Reclassified ordinary `file://`/`loadFile` use as inventory/hardening unless risky context exists.
- Moved parser/file classification earlier in the implementation sequence.

Remaining open questions:

1. How much source-map support is required for v1 large-app tuning?
2. Should the first harness adapter live in this repo as an example, or only in `bug_bounty_harness`?
3. Which Electron Team context packet fields are strictly required for the first Canva dry run?

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
