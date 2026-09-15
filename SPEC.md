# SonarQube VEX Import Plugin — Specification

**Artifact:** `sonar-vex-import-plugin`
**Group:** `org.sonarsource.plugins.veximport`
**Plugin key:** `veximport`
**Current version:** 0.1.0 (pom.xml)
**Minimum SonarQube:** 2025.1 (sonar-plugin-api 11.1.0.2693)
**Last updated:** 2026-09-15

> **Disclaimer:** Personal project — not officially endorsed or supported by Sonar or SonarSource. This plugin writes dependency-risk status changes to SonarQube using an internal, unstable API (see §3.2) — it is not built on a publicly supported contract and can break on a SonarQube upgrade without notice.

---

## 1. Overview

The VEX Import plugin adds a **"VEX Import"** menu item to SonarQube **project** pages only (not applications, portfolios, or sub-portfolios). It runs a five-step wizard that imports a **VEX (Vulnerability Exploitability eXchange)** document — CycloneDX 1.6 JSON — and bulk-updates the status of matching SCA dependency risks to reflect it.

SonarQube ships VEX *export* today (a machine-readable vulnerability posture report compiled from dependency-risk status and status-change comments) but has no in-product VEX *import*. This plugin fills that gap, restricted by design to dependencies SonarQube has **actually detected** on the selected project branch — a VEX statement about a component SonarQube doesn't know about cannot be applied.

## 2. Architecture

### Java entry points

```
VexImportPlugin
  └── VexImportPageDefinition       (PageDefinition)
        └── page "veximport/vex_import"
              scope=COMPONENT, qualifiers=PROJECT only
```

No admin page, no property definition. The Java layer only registers the page; all logic runs in the browser (and, separately, in the companion Python CLI — see §6).

### TypeScript entry point

```
src/main/ts/vex-import.tsx
  └── window.registerExtension("veximport/vex_import", options =>
        <VexImportWizard component={options.component} branchLike={options.branchLike} />)
```

### Component tree

```
VexImportWizard                       (root state container)
  ├── Disclaimer
  ├── [step 1] StepIntro              — workflow explanation, download link for cli/vex-import.py
  ├── [step 2] StepSelectFile         — branch <select> + drag-and-drop / file-picker VEX upload
  ├── [step 3] StepAssessment         — importable-changes table + not-importable table (with reasons)
  ├── [step 4] StepApprove            — optional additional comment, confirmation checkbox, Apply
  └── [step 5] StepResult             — per-item applied/failed result, cross-checked against step 3
```

### Data flow

```
step 2 (file + branch selected)
  │
  ├── parseVex(rawJsonText)            — pure, network-free
  │     → { candidates: [{vulnerabilityId, packageUrl, analysis}], issues: [...] }
  │     document-level problems throw; per-entry problems are collected, not fatal
  │
  ▼
step 3 (entered)
  │
  ├── fetchDetectedRisks(projectKey, branchKey)   ← GET /api/v2/sca/issues-releases
  │     → DetectedRisk[] { issueReleaseKey, vulnerabilityId, packageUrl, status, transitions[] }
  │
  ├── assessImport(parsedVex, detectedRisks)      — pure, network-free
  │     for each VEX candidate:
  │       no matching (vulnerabilityId, packageUrl) in detected risks → blocked
  │       mapAnalysisToTransition(analysis) blocked (state not actionable) → blocked
  │       computed transitionKey not in that risk's transitions[] → blocked
  │       duplicate (vulnerabilityId, packageUrl) within the file → blocked (first wins)
  │       otherwise → importable PlanItem { issueReleaseKey, transitionKey, comment }
  │
  ▼
step 4 (approve)
  │
  ├── user may type an additional comment — appended to every item's comment,
  │     in addition to (not instead of) the one derived from the VEX file:
  │     `${itemComment} — ${userComment}`
  │
  ├── applyStatusChanges(changes)
  │     bulk-first: one POST /api/v2/sca/issues-releases/bulk-change,
  │       ONLY when every item in the batch shares the same transitionKey and comment
  │       (never speculatively — a heterogeneous batch skips bulk entirely)
  │     else/fallback: POST /api/v2/sca/issues-releases/change-status per item,
  │       5 concurrent (utils/concurrentMap.ts)
  │
  ▼
step 5 (result) — per-item success/failure, flags any importable item missing a result
```

---

## 3. VEX Format & Matching

### 3.1 CycloneDX 1.6 fields consumed

| Path | Type | Usage |
|------|------|-------|
| `bomFormat` | string | must equal `"CycloneDX"` — else the whole file is rejected |
| `specVersion` | string | must equal `"1.6"` — else the whole file is rejected |
| `components[].bom-ref` | string | used to resolve `affects[].ref` when it isn't a direct PURL |
| `components[].purl` | string | resolved PURL for a `bom-ref` |
| `vulnerabilities[].id` | string | the CVE (or other) identifier — matched against `vulnerabilityId` |
| `vulnerabilities[].affects[].ref` | string | either a direct `pkg:` PURL, or a `bom-ref` resolved against `components[]` — CycloneDX allows both, and even a common real-world pattern sets `bom-ref` equal to the `purl` string itself |
| `vulnerabilities[].analysis.state` | string | drives the transition mapping (§3.3) |
| `vulnerabilities[].analysis.justification` | string? | used in the generated fallback comment |
| `vulnerabilities[].analysis.response[]` | string[]? | `will_not_fix` distinguishes ACCEPT from CONFIRM for `exploitable` |
| `vulnerabilities[].analysis.detail` | string? | used verbatim as the comment when non-empty |

A single `vulnerabilities[]` entry with multiple `affects[]` produces one matching candidate per affected component.

### 3.2 Matching key

A VEX candidate matches a detected dependency risk on **exact equality of `(vulnerabilityId, packageUrl)`**, including the version embedded in the PURL. CycloneDX's `affects[].versions[]` range syntax is **not** interpreted in v1 — a VEX statement covering a version range must still name the exact PURL SonarQube detected. This is a known v1 limitation, not a design goal.

### 3.3 Analysis state → SonarQube transition

| `analysis.state` | condition | `transitionKey` |
|---|---|---|
| `not_affected` | — | `SAFE` |
| `false_positive` | — | `SAFE` |
| `resolved` | — | `FIXED` |
| `resolved_with_pedigree` | — | `FIXED` |
| `exploitable` | `response[]` includes `will_not_fix` | `ACCEPT` |
| `exploitable` | otherwise | `CONFIRM` |
| `in_triage`, missing, or unrecognized | — | **blocked** — not actionable |

Comment sent with the transition: `analysis.detail` trimmed, if non-empty; otherwise a generated fallback `VEX import: state=<state>[, justification=<justification>]`. This mapping table is duplicated in `cli/vex-import.py` (necessarily — two runtimes) and both copies are annotated `# KEEP IN SYNC WITH ...`; this table is the canonical reference for reviewing both.

### 3.4 Non-importable reasons

A matched-or-unmatched VEX entry is blocked (shown in the step 3 "not importable" table, never applied) for exactly one of:

1. **Not detected** — no detected risk on this project/branch shares the entry's `(vulnerabilityId, packageUrl)`.
2. **Invalid transition** — the computed `transitionKey` isn't in that risk's live `transitions[]` (e.g. already terminal, or the workflow doesn't offer that move from its current status).
3. **Not actionable** — `analysis.state` is `in_triage`, missing, or unrecognized.
4. **Malformed entry** — missing `id`, missing/empty `affects[]`, or an unresolvable `ref` (parser-level).
5. **Duplicate** — a second VEX entry for a `(vulnerabilityId, packageUrl)` pair already seen earlier in the same file (first occurrence wins).

---

## 4. APIs Used

### 4.1 `GET /api/v2/sca/issues-releases`

| Parameter | Value |
|-----------|-------|
| `projectKey` | Project key |
| `branchKey` | Branch name — **required**, no default |
| `pageIndex` | 1-based page number |
| `pageSize` | `500` |

Response envelope's array key varies by server version (`issueReleases` / `issuesReleases` / `items` — all three are tried). Each item's `key` (or `id`) field is the `issueReleaseKey` UUID needed for the write calls below; `transitions[]` lists the valid next `transitionKey` values from the item's current `status`. Confirmed live against a local SonarQube instance during development.

### 4.2 `POST /api/v2/sca/issues-releases/change-status`

Body: `{ issueReleaseKey, transitionKey, comment }`. `SAFE` requires a non-empty `comment` (400 otherwise). Requires **Administer Issues** permission on the project — enforced server-side; the plugin surfaces a 403 as a per-item failure in step 5 rather than gating client-side.

This is an **internal, unstable** SonarQube API — not publicly documented for external write use, though it's the same endpoint SonarQube's own SonarLint and CLI use internally. It can change without notice on a SonarQube upgrade.

### 4.3 `POST /api/v2/sca/issues-releases/bulk-change`

Same semantics, batched: body `{ issueReleaseKeys: [...], transitionKey, comment }`, response is a JSON array of the updated risk objects. **Confirmed live** against a real SonarQube DataCenter Edition instance (`it/vex-smoke-test/`) — the shape matches exactly what this plugin sends. The plugin still only ever calls it when every item in a batch shares the same `transitionKey` and `comment` — never speculatively — and falls back to per-item `change-status` calls otherwise or on any failure, since a VEX import batch is commonly heterogeneous (different risks needing different transitions).

### 4.3a Permission-scoped `transitions[]`

`transitions[]` on a `GET /api/v2/sca/issues-releases` item is **scoped to the calling token's permissions**, not just the risk's workflow state — confirmed live: a token with only `scan`/`provisioning` (no Administer Issues) saw `["CONFIRM"]` for an OPEN risk, while an admin token saw `["ACCEPT","CONFIRM","SAFE"]` for the identical risk at the identical moment. This means the wizard and CLI correctly report fewer importable changes (or more "not importable — invalid transition" entries) for a less-privileged user, for the same VEX file — this is expected server behavior, not a plugin bug, and is worth explaining if a user reports "it says not importable but it should be."

### 4.4 CSRF

POST requests include an `X-XSRF-TOKEN` header set from the `XSRF-TOKEN` cookie (SonarQube's double-submit pattern), via `utils/csrf.ts`.

---

## 5. UI Components

### `VexImportWizard` (`components/VexImportWizard.tsx`)

Root state container. Props: `{ component: { key, name, qualifier? }, branchLike?: { name } }`. Renders a plain "not available" message if `component.qualifier` is set and isn't `TRK` (defense in depth — the page definition already restricts registration to `PROJECT`).

State: `step` (1–5), `selectedBranch`, `vexFile`/`parsedVex`/`parseError`, `detectedRisks` (+loading/error), `userComment`, `applyLoading`/`applyError`/`applyResults`. `assessment` is derived via `useMemo` over `parsedVex` and `detectedRisks`.

### `StepIntro`, `StepSelectFile`, `StepAssessment`, `StepApprove`, `StepResult` (`components/wizard/`)

One component per wizard step, described in §2's data-flow diagram. `StepSelectFile` fetches long-lived branches itself via `fetchLongLivedBranches` (`api/projectBranches.ts`, unchanged from the plugin's previous incarnation), pre-selecting `branchLike?.name` when present, falling back to the project's main branch. `StepApprove` owns the optional additional-comment textarea and the explicit confirmation checkbox that gates the Apply button; wizard navigation is locked (no Back) while the apply call is in flight, to avoid leaving a partial-apply state abandoned mid-way.

### `Disclaimer`, `tableUtils` (`components/shared/`)

Unchanged from the plugin's previous incarnation.

---

## 6. Python CLI companion (`cli/vex-import.py`)

Stdlib-only Python 3 script performing the same parse → fetch → match → apply flow outside the browser, for CI/scripted use. Downloadable from the wizard's step 1 (`/static/veximport/vex-import.py`, copied into the build output alongside the JS bundle — see `scripts/build.js`).

```
vex-import.py --base-url URL --project KEY --branch NAME --vex-file PATH --token TOKEN [--comment TEXT] [--dry-run] [-y]
```

- The script itself never contains or stores a token. The user supplies their own, either via `--token` or the `SONAR_TOKEN` environment variable (`--token` takes precedence when both are set); the env var is documented as the safer choice on a shared machine (avoids shell-history/process-list exposure), but `--token` is supported directly since the script is meant to be runnable standalone.
- `--branch` is required, no default, mirroring the wizard's explicit step 2 selection.
- `--dry-run` fetches, parses, and matches, printing the plan without writing.
- Without `-y`/`--yes`, prints the plan and requires an interactive `y/N` confirmation — the CLI's equivalent of the wizard's step 4 gate.
- Exit codes: `0` success/clean dry-run, `1` usage/validation error, `2` network/auth error, `3` one or more items failed to apply.

The parsing/mapping/matching logic is re-implemented in Python (two runtimes — not worth cross-language codegen for this size). Both copies are annotated `# KEEP IN SYNC WITH <other file>` at the mapping table; §3.3 above is the canonical reference both should be reviewed against.

---

## 7. Known Limitations / TODOs

| # | Area | Description |
|---|------|--------------|
| 1 | Format scope | CycloneDX 1.6 JSON only. XML and CSAF VEX are out of scope for v1. |
| 2 | Matching | Exact `(vulnerabilityId, packageUrl)` string equality, including version — no CycloneDX version-range (`affects[].versions[]`) interpretation. |
| 3 | Bulk endpoint | Confirmed live (see §4.3) — contract matches this plugin's implementation. The fail-safe fallback to per-item calls remains in place regardless, since a heterogeneous batch (the common case) never uses bulk in the first place. |
| 4 | Internal API | Both write endpoints are internal/unstable — no guarantee they survive a SonarQube upgrade unchanged. |
| 5 | Duplicate VEX entries | A second entry for the same `(vulnerabilityId, packageUrl)` in one file is silently blocked as a duplicate (first wins) rather than merged or reported as a file-level error. |
| 6 | Scope | Project-level only, by design — no application/portfolio aggregation (dependency risks don't have a natural "main version" across branches the way issues do, so a cross-project import wouldn't have an unambiguous target). |
| 7 | No pytest suite | The Python CLI has no automated test suite in v1 (no existing Python tooling/CI in this repo); its logic mirrors the TS modules, which are unit-tested. |
