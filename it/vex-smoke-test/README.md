# VEX Import smoke-test fixture

A minimal, disposable project used to manually exercise the VEX Import
plugin end to end against a real SonarQube instance: real detected
dependency risks (via SBOM import, not manifest scanning, so the exact
packages are controlled) on two branches, plus sample VEX files to import
against them.

## 1. Analyze

```bash
export SONAR_HOST_URL=... # your test instance
export SONAR_TOKEN=...    # a token with Administer Issues on this project
./scan.sh
```

This analyzes one placeholder source file on two branches (`main` and
`release-1.0`), each importing a different CycloneDX SBOM
(`sonar.sca.sbomImportPaths`):

| Branch | SBOM | Components |
|---|---|---|
| `main` | `sbom-main.cdx.json` | `log4j-core@2.14.1` (CVE-2021-44228), `lodash@4.17.15` |
| `release-1.0` | `sbom-release.cdx.json` | `log4j-core@2.14.1` (same CVE, different branch), `minimist@1.2.5` |

`log4j-core` is shared across both branches (same CVE, two independent
dependency risks — one per branch) to test that VEX import correctly
branch-scopes its matching. `lodash` and `minimist` are each unique to one
branch, to produce a real "not detected on this branch" case when a VEX
file mentioning the other branch's package is imported.

## 2. Try the VEX Import wizard

Open the project's **VEX Import** page in SonarQube, select `release-1.0`,
and upload one of the files in `vex/`.

## 3. Try the CLI

```bash
python3 ../../cli/vex-import.py \
  --base-url "$SONAR_HOST_URL" --token "$SONAR_TOKEN" \
  --project vex-import-smoke-test --branch release-1.0 \
  --vex-file vex/exploitable.json --dry-run
```

## `vex/` fixtures

| File | Exercises |
|---|---|
| `safe.json` | `not_affected` → `SAFE` (comment required) |
| `exploitable.json` | `exploitable` + `will_not_fix` → `ACCEPT` |
| `resolved.json` | `resolved` → `FIXED` |
| `in-triage.json` | `in_triage` → blocked, not actionable |
| `not-detected.json` | a CVE/package this branch never had → blocked, not detected |

The exact `id` values in these fixtures must match whatever CVE SonarQube's
vulnerability database actually associates with each package/version at
scan time — check the real values via `GET /api/v2/sca/issues-releases`
after running `scan.sh` and adjust if they've drifted (the DB is a moving
target; `log4j-core@2.14.1` / CVE-2021-44228 has been stable for years, but
this isn't guaranteed forever).

This whole directory is disposable — delete the `vex-import-smoke-test`
project from your test instance when done.
