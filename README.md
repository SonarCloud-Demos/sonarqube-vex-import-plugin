# SonarQube VEX Import Plugin

> ⚠️ **Experimental** — This is a personal project, not an official Sonar product. It is not endorsed or supported by SonarSource.

Adds a **VEX Import** page to SonarQube project pages. It imports a VEX (Vulnerability Exploitability eXchange) document — CycloneDX 1.6 JSON — and bulk-updates the status of matching SCA dependency risks to reflect it.

## What it does

SonarQube ships VEX *export* today, but no in-product VEX *import*. This plugin fills that gap: a five-step wizard lets you upload a VEX file (e.g. one supplied by a third-party component vendor), see exactly which of SonarQube's currently detected dependency risks it would change and to what status, approve, and apply.

**Only dependencies SonarQube has actually detected** on the selected project branch can be affected — a VEX statement about a component SonarQube doesn't know about is reported as not importable, with the reason why (not detected, invalid workflow transition, unactionable analysis state, or malformed VEX entry).

### The five steps

1. **Explain** — how the import works, and a download link for the companion Python CLI script that performs the same import from the command line or CI.
2. **Select** — drag-and-drop (or pick) a VEX file, and choose the target branch.
3. **Assess** — review a table of importable changes (current status → new status, package, CVE, comment) and a separate table of VEX entries that cannot be imported, each with a reason.
4. **Approve** — optionally add a comment appended to every imported item (in addition to the justification imported from the VEX file itself), confirm, and apply.
5. **Result** — per-item success or failure, cross-checked against what step 3 assessed.

## Requirements

- SonarQube 2025.1 or later, with Advanced Security / SCA enabled on the project
- **Administer Issues** permission on the target project (Browse alone is enough to view but not to apply)

## Building

```bash
# Build frontend
yarn install && yarn build

# Build plugin JAR
mvn package -DskipTests

# Deploy
cp target/sonar-vex-import-plugin-*.jar $SONARQUBE_HOME/extensions/plugins/
# Restart SonarQube
```

## Testing against a real instance

`it/vex-smoke-test/` is a disposable fixture — a one-file project analyzed on two branches via SBOM import, plus sample VEX files — for manually exercising the wizard and the CLI end to end against a real SonarQube instance. See `it/vex-smoke-test/README.md`.

## Command-line usage

The companion script mirrors the wizard's logic for use from a script or CI pipeline:

```bash
python3 cli/vex-import.py \
  --base-url https://sonarqube.example.com \
  --project my-project \
  --branch main \
  --vex-file report.vex.json \
  --token <your-sonarqube-token> \
  --dry-run
```

The script never contains or stores a token — pass your own via `--token`, or set `SONAR_TOKEN` in your environment instead if you'd rather it not show up in shell history or process listings. Drop `--dry-run` (and add `-y` to skip the confirmation prompt) to apply. See `cli/vex-import.py --help` for all options.

## Disclaimer

This plugin writes dependency-risk status changes to SonarQube via an **internal, unstable API** — the same one SonarQube's own SonarLint and CLI use internally, but not a publicly documented or supported contract for external write use. It can change without notice on a SonarQube upgrade. Status changes are visible in SonarQube's own changelog and can be reversed the same way any manual status change can.
