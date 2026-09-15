#!/usr/bin/env bash
# Smoke-test fixture for the VEX Import plugin.
#
# Analyzes this one-file placeholder project on two branches, each importing
# a different CycloneDX SBOM (sonar.sca.sbomImportPaths) so that real,
# server-matched SCA dependency risks exist to exercise the wizard and the
# CLI against.
#
# Requires SONAR_HOST_URL and SONAR_TOKEN to already be exported in your
# shell before running this script — it does not set or read them from
# anywhere else.
set -euo pipefail

: "${SONAR_HOST_URL:?SONAR_HOST_URL must be exported before running this script}"
: "${SONAR_TOKEN:?SONAR_TOKEN must be exported before running this script}"

PROJECT_KEY="${PROJECT_KEY:-vex-import-smoke-test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== Analyzing $PROJECT_KEY @ main (SBOM: sbom-main.cdx.json) =="
sonar-scanner \
  -Dsonar.projectKey="$PROJECT_KEY" \
  -Dsonar.projectName="VEX Import Smoke Test" \
  -Dsonar.sources="$SCRIPT_DIR" \
  -Dsonar.branch.name=main \
  -Dsonar.sca.sbomImportPaths="$SCRIPT_DIR/sbom-main.cdx.json"

echo
echo "== Analyzing $PROJECT_KEY @ release-1.0 (SBOM: sbom-release.cdx.json) =="
sonar-scanner \
  -Dsonar.projectKey="$PROJECT_KEY" \
  -Dsonar.projectName="VEX Import Smoke Test" \
  -Dsonar.sources="$SCRIPT_DIR" \
  -Dsonar.branch.name=release-1.0 \
  -Dsonar.sca.sbomImportPaths="$SCRIPT_DIR/sbom-release.cdx.json"

echo
echo "Done. Both branches submitted for background analysis — allow a few"
echo "seconds for the SCA risks to appear under:"
echo "  \$SONAR_HOST_URL/api/v2/sca/issues-releases?projectKey=$PROJECT_KEY&branchKey=main"
echo "  \$SONAR_HOST_URL/api/v2/sca/issues-releases?projectKey=$PROJECT_KEY&branchKey=release-1.0"
