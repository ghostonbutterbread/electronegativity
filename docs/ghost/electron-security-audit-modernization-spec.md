# Elecronegativity Modernization Spec

Status: draft
Owner: Ghost / Ryushe
Upstream: https://github.com/doyensec/electronegativity
Local repo: `/home/ryushe/projects/elecronegativity`
Last updated: 2026-05-18

## Goal

Modernize the unmaintained open-source Electronegativity scanner into a deterministic Electron security-audit tool that can feed Ghost's bug bounty harness and Electron Team.

The tool should catch baseline Electron misconfigurations consistently, then emit structured evidence that agents can use for deeper Canva-style trust-boundary analysis.

## Why this exists

Static scanners are more consistent than LLM agents for known Electron checklist issues. Agents are still valuable, but they should reason over scanner output instead of rediscovering baseline config problems from scratch.

This repo should become the repeatable baseline layer:

```text
AppMap -> Elecronegativity scanner -> Electron Team agents -> single-agent trace -> dynamic validation
```

## Scope

### Included

- Keep/refresh the existing Electronegativity-style checklist scanner.
- Update checks against modern Electron security documentation.
- Add structured JSON/SARIF output fields useful to Ghost's harness.
- Add hypothesis-oriented output for downstream agents.
- Add tests/fixtures for modern Electron patterns.
- Preserve upstream license/attribution.

### Non-goals

- Do not replace AppMap.
- Do not replace Electron Team agents.
- Do not perform live application interaction or CDP-based validation.
- Do not claim a finding is exploitable without a reachable source-to-sink path.

## Initial check families

1. Browser/window hardening
   - `nodeIntegration`
   - `contextIsolation`
   - `sandbox`
   - `webSecurity`
   - `allowRunningInsecureContent`
   - `devTools`
   - unsafe `BrowserWindow`, `BrowserView`, and `WebContentsView` options

2. Preload and bridge exposure
   - `contextBridge.exposeInMainWorld`
   - direct `ipcRenderer` exposure
   - broad object/function exposure
   - exposed wrappers that forward arbitrary channels or payloads
   - preload scripts with unexpected Node/Electron access

3. IPC contract safety
   - `ipcMain.handle/on` channel inventory
   - sender/origin validation
   - arbitrary channel forwarding
   - risky sinks reachable from IPC: filesystem, shell, native helpers, export/import, account/session actions

4. Navigation, protocol, and external-open safety
   - `setWindowOpenHandler`
   - `will-navigate`, `new-window`, `web-contents-created`
   - `shell.openExternal`
   - custom protocol registration and privilege flags
   - deeplink URL parsing and allowlist handling

5. Renderer JavaScript execution surfaces
   - `innerHTML`, `outerHTML`, `insertAdjacentHTML`
   - `DOMParser`, `Range.createContextualFragment`
   - `iframe.srcdoc`, dynamic script creation
   - `eval`, `Function`, dynamic import-like patterns
   - markdown/HTML/rich-text renderers and sanitizer use

6. Content/vector labels
   - file import/upload
   - export/preview
   - pasted content
   - comments/collaboration
   - templates/assets
   - AI generated or AI consumed content
   - custom protocol/deeplink input

## Output contract

The scanner should emit normal findings and agent-ready hypotheses.

Each finding/hypothesis should include:

- `check_id`
- `title`
- `severity`
- `confidence`
- `file`
- `line`
- `evidence`
- `electron_component` such as `main`, `preload`, `renderer`, `protocol`, `ipc`
- `affected_window_or_channel` when known
- `source_label` when known
- `sink_label` when known
- `trust_boundary`
- `next_agent_hint`
- `appmap_refs` when provided by the harness

Hypotheses should prefer this chain shape:

```text
source -> render/sink -> execution context -> bridge/IPC reachability -> impact hypothesis
```

## Harness integration plan

- Add a bug bounty harness wrapper/profile named `electron_security_audit`.
- Run this scanner before broad Electron agents.
- Import JSON/SARIF/hypothesis output into Electron Team context packets.
- Let agents reason over ranked scanner evidence instead of duplicating deterministic checks.
- Dynamic validation remains a separate, explicitly approved step.

## First implementation phases

### Phase 0 — Repo safety and baseline

- Preserve upstream remote as `upstream`.
- Add local modernization spec.
- Run existing tests/build to establish baseline.
- Add a fixture app if needed.

### Phase 1 — Modern docs/check inventory

- Map current Electron security docs to existing checks.
- Identify stale checks, missing APIs, and renamed/deprecated patterns.
- Add check inventory documentation.

### Phase 2 — Structured output

- Ensure machine-readable JSON/SARIF is stable.
- Add Ghost hypothesis JSONL output.
- Add deterministic check IDs and evidence fields.

### Phase 3 — Modern check expansion

- Add/refresh IPC, preload, navigation/protocol, permissions, and renderer-sink checks.
- Add tests for each check family.

### Phase 4 — Harness wrapper

- Add a wrapper in `bug_bounty_harness` that runs this scanner and imports results.
- Feed results into Electron Team baseline/hypothesis mode.

## Success criteria

- The tool runs against Canva's extracted `app.asar` source and emits deterministic structured output.
- It catches generic Electron security-page misconfigurations without needing an LLM agent.
- It emits ranked hypotheses that Electron Team agents can consume.
- It has tests for newly added checks.
- It remains safe/read-only against target applications.
