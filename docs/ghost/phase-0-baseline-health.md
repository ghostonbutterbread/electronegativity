# Phase 0 Baseline Health

Status: reviewed
Owner: Ghost
Reviewer: Codex CLI review completed 2026-05-18
Date: 2026-05-18
Branch: `ghost/electron-security-audit-spec`
Spec: `docs/ghost/electron-audit-buildout-spec.md`

## Goal

Establish the current repository health before implementation begins.

Phase 0 exit criteria from the spec:

- Known baseline test result is recorded.
- No implementation begins before baseline is understood.

## Environment

```text
Node: v24.13.1
npm: 11.9.0
OS: Linux 6.17.0-23-generic x86_64 GNU/Linux
package-lock lockfileVersion: 1
Project Node pin: none observed (`.nvmrc` absent, `.node-version` absent, no `engines` field in package.json)
```

This baseline is therefore tied to the current local toolchain. Future CI/release work should pin or explicitly document supported Node/npm versions before treating test results as broadly reproducible.

## Commands run

```bash
cd /home/ryushe/projects/electronegativity
node -e "const p=require('./package.json'); console.log(JSON.stringify(p.scripts||{},null,2));"
npm test
npm ci
npm test
```

## Results

### Initial `npm test`

Failed because dependencies were not installed:

```text
node_modules missing
package-lock present
sh: 1: rimraf: not found
```

This was expected for a fresh clone/worktree without `node_modules`.

### `npm ci`

Completed successfully.

Notable install warnings:

- `package-lock.json` was created by an older npm version, so npm fetched supplemental metadata.
- Multiple deprecated dependencies are present, including old Babel/core-js/glob/rimraf/asar/tar/eslint-related packages.
- npm reported `47 vulnerabilities`:
  - 2 low
  - 9 moderate
  - 14 high
  - 22 critical

No automatic `npm audit fix` was run because dependency modernization should be handled deliberately in a later phase; forced fixes may cause broad breaking changes.

### Post-install `npm test`

Passed.

```text
974 passing (4s)
```

Warnings/noise observed during test:

- npm warns about unknown `min-release-age` config.
- Node warning: package lacks explicit module type and reparses test files as ES modules.
- `AvailableSecurityFixesGlobalCheck` fetched Electron release metadata and updated release list to `v22.0.0`; this indicates tests can perform network/update behavior.
- CSP test emitted: `Could not retrieve updated translations for the current locale`.

### Test hermeticity notes

The current tests are not fully hermetic:

- `src/finder/checks/GlobalChecks/AvailableSecurityFixesGlobalCheck.js` calls GitHub release metadata via `got.head(...)` and `got(...)`, then writes/deletes cached `releases.<etag>.json` files under the shared temp directory from `temp-dir`.
- `src/locales/i18n.js` calls the configured S3 `i18nSource` to fetch locale JSON and falls back locally on failure.

Before CI hardening or deterministic snapshot testing, these network/cache paths should be mocked, disabled behind a test flag, or run with an isolated `TMPDIR` and offline fixtures.

## Baseline interpretation

The current fork is buildable and testable after `npm ci`.

Current baseline is acceptable for starting Phase 1, with these risks tracked:

1. Dependency stack is old and vulnerable. The current baseline should not be used on untrusted third-party app bundles/repos without sandboxing or dependency exposure triage, because the scanner parses/extracts source and `.asar` files using old runtime dependencies. Do not run arbitrary target apps or untrusted install scripts through this repo. Treat dependency modernization as a separate controlled task.
2. Existing tests perform network fetch/update behavior and use shared temp cache paths. Future test hardening should isolate or mock release metadata and locale fetches where possible.
3. Build output is generated under `dist/`; current repository status remained clean after the baseline run and before adding this report.
4. Current parser/test stack is old but functional enough to support incremental modernization.

## Git status after baseline

```text
clean before writing this baseline report
```

## Reviewer resolution

Codex reviewer agreed Phase 0 is satisfied but requested three baseline clarifications before moving on:

- environment/toolchain details,
- non-hermetic network/temp-cache behavior,
- stronger wording about vulnerable dependencies and untrusted app bundle parsing.

Those edits are incorporated in this reviewed version.

## Phase 0 conclusion

Phase 0 passes after dependency installation:

- `npm ci`: passed
- `npm test`: passed, 974 tests
- repository remained clean before adding this report

Recommended next phase: Phase 1 parser modernization and file classification.
