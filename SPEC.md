# SonarQube VEX Import Plugin — Specification

**Artifact:** `sonar-vex-import-plugin`
**Group:** `org.sonarsource.plugins.veximport`
**Plugin key:** `veximport`
**Current version:** 0.1.0 (pom.xml)
**Minimum SonarQube:** 2025.1 (sonar-plugin-api 11.1.0.2693)
**Last updated:** 2026-09-16

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
  ├── ['intro']      StepIntro         — workflow explanation, download link for cli/vex-import.py
  ├── ['selectFile'] StepSelectFile    — branch <select> + drag-and-drop / file-picker VEX upload
  ├── ['assessment'] StepAssessment    — importable-changes table + not-importable table (with reasons)
  ├── ['conflicts']  StepConflicts     — CONDITIONAL, only when assessment.conflicts.length > 0 —
  │                                      bulk + per-row Keep SonarQube / Apply VEX resolution
  ├── ['approve']    StepApprove       — optional additional comment, confirmation checkbox, Apply
  └── ['result']     StepResult        — per-item applied/failed result, cross-checked against assessment
```

`WizardStep` is a named string union, not a numeric sequence — `'conflicts'` is skipped entirely (both forward and backward navigation) when there are no conflicts, which a fixed `1|2|3|4|5` numbering couldn't express cleanly.

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
  ├── assessImport(parsedVex, detectedRisks, fetchIssueReleaseChangelog)   — async
  │     phase 1 (synchronous matching, unchanged):
  │       no matching (vulnerabilityId, packageUrl) in detected risks → blocked
  │       mapAnalysisToTransition(analysis) blocked (state not actionable) → blocked
  │       computed transitionKey not in that risk's transitions[] → blocked
  │       duplicate (vulnerabilityId, packageUrl) within the file → blocked (first wins)
  │       otherwise → provisional { PlanItem, vexReferenceDate }
  │     phase 2 (5-concurrent, per provisional item — utils/concurrentMap.ts):
  │       GET .../changelogs (§4.2), findLastStatusChange(...)
  │       fetch failed → blocked ("could not verify...")
  │       no status-change history → importable PlanItem
  │       history exists + VEX date missing/older → conflicts ConflictItem
  │       history exists + VEX date same-or-newer → importable PlanItem
  │
  ▼
step 3.5 (conflicts, conditional — only rendered when conflicts.length > 0)
  │
  ├── one row per conflict: SonarQube's current status/last-change date+user+comment
  │     side-by-side with the VEX's proposed status/reference date/comment
  ├── resolution state: Map<issueReleaseKey, 'keep'|'apply'>, default 'keep' when absent
  │     from the map; a bulk control replaces the whole map, a per-row control sets
  │     one entry — both write to the same map, no separate "bulk mode" flag
  │
  ▼
step 4 (approve)
  │
  ├── finalImportable = assessment.importable ++ conflicts resolved as 'apply'
  │
  ├── user may type an additional comment — appended to every item's comment,
  │     in addition to (not instead of) the one derived from the VEX file:
  │     `${itemComment} — ${userComment}`
  │
  ├── applyStatusChanges(changes)                 (changes built from finalImportable)
  │     bulk-first: one POST /api/v2/sca/issues-releases/bulk-change,
  │       ONLY when every item in the batch shares the same transitionKey and comment
  │       (never speculatively — a heterogeneous batch skips bulk entirely)
  │     else/fallback: POST /api/v2/sca/issues-releases/change-status per item,
  │       5 concurrent (utils/concurrentMap.ts)
  │
  ▼
step 5 (result) — per-item success/failure, flags any finalImportable item missing a result
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
| `vulnerabilities[].analysis.lastUpdated` | string? | official CycloneDX field (added in spec v1.5, present in 1.6) — highest-priority source for the VEX reference date (§3.5) |
| `vulnerabilities[].analysis.firstIssued` | string? | official CycloneDX field, same v1.5+ origin — second-priority source for the VEX reference date (§3.5); confirmed present in SonarQube's own VEX export |
| `metadata.timestamp` | string? | whole-document export/generation date — lowest-priority fallback for the VEX reference date (§3.5) |

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

### 3.5 VEX reference date & conflict detection

Each candidate carries a best-effort **VEX reference date**, computed as `analysis.lastUpdated ?? analysis.firstIssued ?? document metadata.timestamp ?? undefined` — a plain string carried through by `parseVex.ts` with no parsing/validation at this stage (see `vex/parseVex.ts`'s `VexCandidate.vexReferenceDate`). None of the three sources is guaranteed to be present; a minimal hand-authored VEX file may have no date information at all.

For every candidate that would otherwise be importable (matched, transition valid, state actionable — §3.2–§3.4), `assessImport.ts` additionally fetches that risk's changelog (§4.2) and finds the most recent `fieldName: "status"` entry, i.e. the last time a human (or another tool) manually changed this risk's status in SonarQube. Classification:

| SonarQube last status-change | VEX reference date | Outcome |
|---|---|---|
| none (never manually transitioned) | any | **importable** — nothing to conflict with |
| exists | missing, or older than the SonarQube date | **conflict** |
| exists | same instant or newer than the SonarQube date | **importable** |
| — | — | changelog fetch itself failed → **blocked** (`could not verify SonarQube status-change history: ...`) — never guessed as either importable or a resolvable conflict, since the plugin has no data to decide with |

An unparseable VEX reference-date string is treated identically to a missing one (falls into the "conflict" row), not as a parse error. Equal timestamps count as "no conflict" (same-or-newer). This check happens **before** any write — see §4.3's note that writes can never be backdated, which is why the comparison has to happen here rather than being enforced server-side.

Conflicts are a third bucket alongside `importable`/`blocked` (`AssessmentResult.conflicts: ConflictItem[]`), each carrying both sides needed for the approval UI: the would-be `PlanItem`, the VEX reference date, and SonarQube's last-change date/user/comment. They are **not** auto-applied — see §5's `StepConflicts` for how the user resolves them.

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

### 4.2 `GET /api/v2/sca/issues-releases/{issueReleaseKey}/changelogs`

Returns the full change history for one risk: `{ changelog: [ { key, createdAt, user: {login, name}, markdownComment, htmlComment, changeData: [ { fieldName, oldValue, newValue } ], actions } ] }`. **Confirmed live** — a status transition produces an entry with `changeData: [{fieldName: "status", oldValue, newValue}]` (this literal `fieldName` value is what `findLastStatusChange` in `api/scaChangelog.ts` filters on). No pagination envelope has been observed (see §7).

This is the **only** way to get a per-risk last-status-change timestamp — `GET /api/v2/sca/issues-releases` (list) and its single-item form only expose `createdAt` (risk *detection* date, never a change date). Used by the conflict guard (§3.5) to detect when a VEX statement is older than a decision already made manually in SonarQube. An empty result, or one with no `fieldName: "status"` entries, means the risk has never been manually transitioned — no conflict is possible.

### 4.3 `POST /api/v2/sca/issues-releases/change-status`

Body: `{ issueReleaseKey, transitionKey, comment }`. `SAFE` requires a non-empty `comment` (400 otherwise). Requires **Administer Issues** permission on the project — enforced server-side; the plugin surfaces a 403 as a per-item failure in step 5 rather than gating client-side.

This is an **internal, unstable** SonarQube API — not publicly documented for external write use, though it's the same endpoint SonarQube's own SonarLint and CLI use internally. It can change without notice on a SonarQube upgrade. No date field exists in this request schema — **an imported VEX file's own date can never be written back into SonarQube as a structured field**, only as free text inside `comment`. This is exactly why the conflict guard (§3.5) has to compare dates client-side, before the write, rather than relying on SonarQube to reject a stale write itself.

### 4.4 `POST /api/v2/sca/issues-releases/bulk-change`

Same semantics, batched: body `{ issueReleaseKeys: [...], transitionKey, comment }`, response is a JSON array of the updated risk objects. **Confirmed live** against a real SonarQube DataCenter Edition instance (`it/vex-smoke-test/`) — the shape matches exactly what this plugin sends. The plugin still only ever calls it when every item in a batch shares the same `transitionKey` and `comment` — never speculatively — and falls back to per-item `change-status` calls otherwise or on any failure, since a VEX import batch is commonly heterogeneous (different risks needing different transitions).

### 4.4a Permission-scoped `transitions[]`

`transitions[]` on a `GET /api/v2/sca/issues-releases` item is **scoped to the calling token's permissions**, not just the risk's workflow state — confirmed live: a token with only `scan`/`provisioning` (no Administer Issues) saw `["CONFIRM"]` for an OPEN risk, while an admin token saw `["ACCEPT","CONFIRM","SAFE"]` for the identical risk at the identical moment. This means the wizard and CLI correctly report fewer importable changes (or more "not importable — invalid transition" entries) for a less-privileged user, for the same VEX file — this is expected server behavior, not a plugin bug, and is worth explaining if a user reports "it says not importable but it should be."

### 4.5 CSRF

POST requests include an `X-XSRF-TOKEN` header set from the `XSRF-TOKEN` cookie (SonarQube's double-submit pattern), via `utils/csrf.ts`.

---

## 5. UI Components

### `VexImportWizard` (`components/VexImportWizard.tsx`)

Root state container. Props: `{ component: { key, name, qualifier? }, branchLike?: { name } }`. Renders a plain "not available" message if `component.qualifier` is set and isn't `TRK` (defense in depth — the page definition already restricts registration to `PROJECT`).

State: `step` (`WizardStep`, a named union — see §2), `selectedBranch`, `vexFile`/`parsedVex`/`parseError`, `assessment`/`assessmentLoading`/`assessmentError`, `conflictResolutions` (`Map<issueReleaseKey, 'keep'|'apply'>`), `userComment`, `applyLoading`/`applyError`/`applyResults`. `assessment` is now loaded via an explicit async pipeline (`goToAssessment`: `fetchDetectedRisks` then `assessImport(parsedVex, risks, fetchIssueReleaseChangelog)`) rather than a pure `useMemo`, since matching now requires network calls (the changelog fetch per candidate). `finalImportable` is derived via `useMemo` over `[assessment, conflictResolutions]` — `assessment.importable` concatenated with whichever conflicts are resolved as `'apply'` — and is the single value `StepApprove`/`StepResult` consume (they no longer see the full `AssessmentResult`).

### `StepIntro`, `StepSelectFile`, `StepAssessment`, `StepApprove`, `StepResult` (`components/wizard/`)

One component per wizard step, described in §2's data-flow diagram. `StepSelectFile` fetches long-lived branches itself via `fetchLongLivedBranches` (`api/projectBranches.ts`, unchanged from the plugin's previous incarnation), pre-selecting `branchLike?.name` when present, falling back to the project's main branch. `StepApprove` owns the optional additional-comment textarea and the explicit confirmation checkbox that gates the Apply button; wizard navigation is locked (no Back) while the apply call is in flight, to avoid leaving a partial-apply state abandoned mid-way.

### `StepConflicts` (`components/wizard/StepConflicts.tsx`)

Rendered only when `assessment.conflicts.length > 0` (the wizard container decides this, not the step itself — both `StepAssessment`'s Next and `StepApprove`'s Back skip straight past it otherwise). Resolution state is a single `Map<issueReleaseKey, 'keep'|'apply'>` owned by `VexImportWizard` — there is no separate "bulk mode" flag. The two bulk buttons ("Keep SonarQube for all" / "Apply VEX for all") are just a convenience that replaces the whole map; a per-row `<select>` sets one entry; whichever action (bulk or per-row) happens last wins, since both write to the same map. A row with no entry in the map reads as `'keep'` via `resolutions.get(key) ?? 'keep'` — that fallback *is* the default, nothing needs to pre-populate the map when conflicts first appear. The Next button has no gating condition: leaving every row at the default "keep" is a valid, safe choice.

### `Disclaimer`, `tableUtils` (`components/shared/`)

Unchanged from the plugin's previous incarnation.

---

## 6. Python CLI companion (`cli/vex-import.py`)

Stdlib-only Python 3 script performing the same parse → fetch → match → apply flow outside the browser, for CI/scripted use. Downloadable from the wizard's step 1 (`/static/veximport/vex-import.py`, copied into the build output alongside the JS bundle — see `scripts/build.js`).

```
vex-import.py --base-url URL --project KEY --branch NAME --vex-file PATH --token TOKEN
              [--comment TEXT] [--conflict-resolution keep|apply|ask] [--dry-run] [-y]
```

- The script itself never contains or stores a token. The user supplies their own, either via `--token` or the `SONAR_TOKEN` environment variable (`--token` takes precedence when both are set); the env var is documented as the safer choice on a shared machine (avoids shell-history/process-list exposure), but `--token` is supported directly since the script is meant to be runnable standalone.
- `--branch` is required, no default, mirroring the wizard's explicit step 2 selection.
- `--conflict-resolution` (default `ask`) mirrors the wizard's `StepConflicts`: `ask` prints both sides of each conflict and prompts `y/N` interactively (default no = keep); `keep` and `apply` resolve every conflict the same way with no prompting, for CI/scripted use. **Never prompts during `--dry-run`** — conflicts are still listed in the plan output, just not interactively resolved, keeping dry-run non-interactive and side-effect-free.
- `--dry-run` fetches, parses, and matches, printing the plan (including the conflicts section) without writing.
- Without `-y`/`--yes`, prints the plan and requires an interactive `y/N` confirmation — the CLI's equivalent of the wizard's step 5 gate. This confirmation covers the final apply set (`importable` plus whatever `--conflict-resolution` decided to include), not just `importable` alone.
- Exit codes: `0` success/clean dry-run, `1` usage/validation error, `2` network/auth error, `3` one or more items failed to apply.

The parsing/mapping/matching/changelog logic is re-implemented in Python (two runtimes — not worth cross-language codegen for this size), sequentially rather than the wizard's 5-concurrent fetch (matches this script's existing fully-sequential apply loop and stdlib-only ethos — slower for a VEX file with many conflicts, accepted as a tradeoff). Each function is annotated `# KEEP IN SYNC WITH <TS file>`; §3.3/§3.5 above are the canonical references both should be reviewed against.

---

## 7. Known Limitations / TODOs

| # | Area | Description |
|---|------|--------------|
| 1 | Format scope | CycloneDX 1.6 JSON only. XML and CSAF VEX are out of scope for v1. |
| 2 | Matching | Exact `(vulnerabilityId, packageUrl)` string equality, including version — no CycloneDX version-range (`affects[].versions[]`) interpretation. |
| 3 | Bulk endpoint | Confirmed live (see §4.4) — contract matches this plugin's implementation. The fail-safe fallback to per-item calls remains in place regardless, since a heterogeneous batch (the common case) never uses bulk in the first place. |
| 4 | Internal API | Both write endpoints are internal/unstable — no guarantee they survive a SonarQube upgrade unchanged. Internal/DAO-level access was investigated as an alternative and confirmed architecturally impossible for a third-party plugin (SonarQube's plugin classloader allow-list excludes `org/sonar/db/*` and `com/sonar/sca/*` entirely) — the public API, unstable as it is, is the only available path. |
| 5 | Duplicate VEX entries | A second entry for the same `(vulnerabilityId, packageUrl)` in one file is silently blocked as a duplicate (first wins) rather than merged or reported as a file-level error. |
| 6 | Scope | Project-level only, by design — no application/portfolio aggregation (dependency risks don't have a natural "main version" across branches the way issues do, so a cross-project import wouldn't have an unambiguous target). |
| 7 | No pytest suite | The Python CLI has no automated test suite in v1 (no existing Python tooling/CI in this repo); its logic mirrors the TS modules, which are unit-tested, plus a manual smoke check run during development. |
| 8 | Changelog pagination | No pagination envelope has been observed on `GET .../changelogs` (§4.2) — only `{changelog: [...]}`. A risk with an unusually long status-change history could theoretically have older entries missed if SonarQube ever paginates this endpoint; not defended against, since there's no confirmed contract to defend against yet. |
| 9 | Changelog-fetch failure | Blocks that item entirely (with a reason) rather than presenting it as a resolvable conflict — the plugin has no data to decide with, so it doesn't guess either way. |
| 10 | Conflict noise | Most real-world VEX files carry none of the three reference-date fields (`analysis.lastUpdated`/`firstIssued`/document `metadata.timestamp`). Any matched item whose SonarQube status was ever manually changed will land in "conflict" by default in that case (the no-VEX-date arm of §3.5's table) — this can make the conflict step noisy for such files. `StepIntro` calls this out, but it's a real UX cost of the safety-first default, not a bug. |
| 11 | `blocked[]` ordering | No longer fully document-order-preserving: phase-1 blocks (parser/matching-level) keep VEX file order among themselves, but phase-2 blocks (changelog-fetch failures) are appended afterward in fetch-completion order, not interleaved back into file order. Cosmetic only — no test or UI depends on cross-phase ordering. |

### Toolchain

Dev/build/test dependencies (`package.json` devDependencies, `pom.xml` test-scope deps) are kept CVE-free by tracking upstream advisories and bumping regularly — not a one-time pass. `esbuild` is pinned at `0.19.2`: newer versions drop support for downleveling destructuring against this project's old browser targets (`chrome58`/`firefox57`/`safari11`/`edge18` in the esbuild build config), so it's held back deliberately rather than out of neglect. Runtime dependencies (React 16.14.0, the SonarQube UI toolkit) are pinned to what the host SonarQube version's plugin API supports and are out of scope for CVE-driven bumps.
