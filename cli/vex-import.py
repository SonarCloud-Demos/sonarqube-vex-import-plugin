#!/usr/bin/env python3
"""Import a CycloneDX 1.6 VEX file into SonarQube dependency-risk statuses.

Mirrors the VEX Import wizard's matching/mapping logic (see
src/main/ts/vex/parseVex.ts, transitionMapping.ts, assessImport.ts) for use
from a script or CI pipeline. Only dependencies SonarQube has actually
detected on the target project branch can be affected.

Usage:
    python3 vex-import.py \\
        --base-url https://sonarqube.example.com \\
        --project my-project \\
        --branch main \\
        --vex-file report.vex.json \\
        --token <your-sonarqube-token> \\
        [--dry-run] [-y]

This script never contains or stores a token — you provide your own, either
via --token or the SONAR_TOKEN environment variable (the latter is preferred
if you're worried about the token showing up in shell history or process
listings on a shared machine).

Exit codes:
    0  success (or a clean --dry-run)
    1  usage / validation error
    2  network / auth error
    3  one or more items failed to apply
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

EXIT_OK = 0
EXIT_USAGE_ERROR = 1
EXIT_NETWORK_ERROR = 2
EXIT_PARTIAL_FAILURE = 3


class UsageError(Exception):
    pass


class NetworkError(Exception):
    pass


# --- VEX parsing -------------------------------------------------------------
# KEEP IN SYNC WITH src/main/ts/vex/parseVex.ts


def parse_vex(raw_text):
    """Returns (candidates, issues). candidates: list of dicts with
    vulnerability_id, package_url, analysis. issues: list of dicts with
    vulnerability_id, package_url, reason — per-entry problems that don't
    block the rest of the file."""
    try:
        doc = json.loads(raw_text)
    except ValueError as e:
        raise UsageError(f'File is not valid JSON: {e}')

    if doc.get('bomFormat') != 'CycloneDX':
        raise UsageError('Not a CycloneDX document (missing or incorrect bomFormat).')
    if doc.get('specVersion') != '1.6':
        raise UsageError('Unsupported CycloneDX specVersion — only 1.6 is supported.')
    vulnerabilities = doc.get('vulnerabilities')
    if not isinstance(vulnerabilities, list):
        raise UsageError('No vulnerabilities[] array found in this VEX document.')

    components_by_bom_ref = {}
    for component in doc.get('components') or []:
        bom_ref = component.get('bom-ref')
        purl = component.get('purl')
        if bom_ref and purl:
            components_by_bom_ref[bom_ref] = purl

    def resolve_package_url(ref):
        if ref.startswith('pkg:'):
            return ref
        bom_ref = ref.rsplit('#', 1)[-1] if '#' in ref else ref
        return components_by_bom_ref.get(bom_ref)

    candidates = []
    issues = []

    for vuln in vulnerabilities:
        vuln_id = vuln.get('id')
        if not vuln_id:
            issues.append({'vulnerability_id': None, 'package_url': None, 'reason': 'missing vulnerability id (CVE)'})
            continue

        affects = vuln.get('affects') or []
        if not affects:
            issues.append({'vulnerability_id': vuln_id, 'package_url': None, 'reason': 'no affected component reference in VEX entry'})
            continue

        for affect in affects:
            ref = affect.get('ref')
            package_url = resolve_package_url(ref) if ref else None
            if not package_url:
                issues.append({
                    'vulnerability_id': vuln_id,
                    'package_url': None,
                    'reason': f'could not resolve component reference "{ref}" to a package URL',
                })
                continue
            candidates.append({'vulnerability_id': vuln_id, 'package_url': package_url, 'analysis': vuln.get('analysis')})

    return candidates, issues


# --- Analysis -> transition mapping -------------------------------------------
# KEEP IN SYNC WITH src/main/ts/vex/transitionMapping.ts

def map_analysis_to_transition(analysis):
    """Returns (blocked, transition_key_or_reason, comment)."""
    if not analysis or not analysis.get('state'):
        return True, 'VEX entry has no analysis.state', None

    state = analysis['state']
    response = analysis.get('response') or []

    if state in ('not_affected', 'false_positive'):
        transition_key = 'SAFE'
    elif state in ('resolved', 'resolved_with_pedigree'):
        transition_key = 'FIXED'
    elif state == 'exploitable':
        transition_key = 'ACCEPT' if 'will_not_fix' in response else 'CONFIRM'
    else:
        return True, f"VEX analysis.state '{state}' is not actionable", None

    detail = (analysis.get('detail') or '').strip()
    if detail:
        comment = detail
    else:
        justification = analysis.get('justification')
        suffix = f', justification={justification}' if justification else ''
        comment = f'VEX import: state={state}{suffix}'

    return False, transition_key, comment


# --- Matching against SonarQube's detected risks ------------------------------
# KEEP IN SYNC WITH src/main/ts/vex/assessImport.ts

def assess_import(candidates, issues, detected_risks):
    """detected_risks: list of dicts with issue_release_key, vulnerability_id,
    package_url, status, transitions. Returns (importable, blocked)."""
    blocked = [dict(i) for i in issues]

    detected_by_key = {}
    for risk in detected_risks:
        if risk.get('vulnerability_id') and risk.get('package_url'):
            detected_by_key[(risk['vulnerability_id'], risk['package_url'])] = risk

    importable = []
    seen = set()

    for candidate in candidates:
        key = (candidate['vulnerability_id'], candidate['package_url'])

        if key in seen:
            blocked.append({
                'vulnerability_id': candidate['vulnerability_id'],
                'package_url': candidate['package_url'],
                'reason': 'duplicate VEX entry for this CVE/package — the first occurrence was used',
            })
            continue
        seen.add(key)

        risk = detected_by_key.get(key)
        if not risk:
            blocked.append({
                'vulnerability_id': candidate['vulnerability_id'],
                'package_url': candidate['package_url'],
                'reason': 'SonarQube did not detect this dependency on this branch',
            })
            continue

        is_blocked, transition_key_or_reason, comment = map_analysis_to_transition(candidate.get('analysis'))
        if is_blocked:
            blocked.append({
                'vulnerability_id': candidate['vulnerability_id'],
                'package_url': candidate['package_url'],
                'reason': transition_key_or_reason,
            })
            continue

        transition_key = transition_key_or_reason
        if transition_key not in risk['transitions']:
            blocked.append({
                'vulnerability_id': candidate['vulnerability_id'],
                'package_url': candidate['package_url'],
                'reason': f"transition {transition_key} is not valid from current status {risk['status']} for this risk",
            })
            continue

        importable.append({
            'issue_release_key': risk['issue_release_key'],
            'vulnerability_id': candidate['vulnerability_id'],
            'package_url': candidate['package_url'],
            'current_status': risk['status'],
            'transition_key': transition_key,
            'comment': comment,
        })

    return importable, blocked


# --- SonarQube API calls -------------------------------------------------------

def api_get(base_url, token, path):
    req = urllib.request.Request(f'{base_url}{path}', headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        raise NetworkError(f'GET {path} failed: HTTP {e.code} — {e.read().decode("utf-8", "replace")}')
    except urllib.error.URLError as e:
        raise NetworkError(f'GET {path} failed: {e.reason}')


def api_post(base_url, token, path, body):
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(
        f'{base_url}{path}',
        data=data,
        method='POST',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req) as res:
            res.read()
            return True, None
    except urllib.error.HTTPError as e:
        return False, f'HTTP {e.code} — {e.read().decode("utf-8", "replace")}'
    except urllib.error.URLError as e:
        return False, str(e.reason)


def fetch_detected_risks(base_url, token, project, branch):
    risks = []
    page_index = 1
    page_size = 500
    while True:
        raw = api_get(base_url, token, f'/api/v2/sca/issues-releases?projectKey={project}&branchKey={branch}&pageIndex={page_index}&pageSize={page_size}')
        items = raw.get('issueReleases') or raw.get('issuesReleases') or raw.get('items') or []
        for item in items:
            key = item.get('key') or item.get('id')
            if not key:
                continue
            risks.append({
                'issue_release_key': key,
                'vulnerability_id': item.get('vulnerabilityId'),
                'package_url': (item.get('release') or {}).get('packageUrl'),
                'status': item.get('status', 'OPEN'),
                'transitions': item.get('transitions') or [],
            })
        page = raw.get('page') or raw.get('paging') or {}
        page_size_actual = page.get('pageSize', page_size)
        total = page.get('total', len(items))
        if not items or page_index * page_size_actual >= total:
            break
        page_index += 1
    return risks


def print_plan(importable, blocked):
    print(f'\nImportable changes ({len(importable)}):')
    for item in importable:
        print(f"  {item['vulnerability_id']} / {item['package_url']}: {item['current_status']} -> {item['transition_key']}  ({item['comment']})")
    print(f'\nNot importable ({len(blocked)}):')
    for item in blocked:
        print(f"  {item.get('vulnerability_id') or '—'} / {item.get('package_url') or '—'}: {item['reason']}")
    print()


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base-url', required=True, help='SonarQube base URL, e.g. https://sonarqube.example.com')
    parser.add_argument('--project', required=True, help='Project key')
    parser.add_argument('--branch', required=True, help='Target branch name (no default — must be explicit)')
    parser.add_argument('--vex-file', required=True, help='Path to the CycloneDX 1.6 VEX JSON file')
    parser.add_argument('--token', default=None, help='SonarQube user token. Prefer the SONAR_TOKEN environment variable over this flag if you want to avoid the token appearing in shell history or process listings. This script never embeds or stores a token itself.')
    parser.add_argument('--comment', default='', help='Optional comment appended to every imported item, in addition to the justification imported from the VEX file')
    parser.add_argument('--dry-run', action='store_true', help='Print the plan without applying any changes')
    parser.add_argument('-y', '--yes', action='store_true', help='Apply without an interactive confirmation prompt')
    args = parser.parse_args(argv)

    token = args.token or os.environ.get('SONAR_TOKEN')
    if not token and not args.dry_run:
        raise UsageError('A token is required: pass --token or set the SONAR_TOKEN environment variable (not needed for --dry-run against a public instance, but almost always needed).')

    with open(args.vex_file, 'r', encoding='utf-8') as f:
        raw_text = f.read()
    candidates, issues = parse_vex(raw_text)

    base_url = args.base_url.rstrip('/')
    detected_risks = fetch_detected_risks(base_url, token, args.project, args.branch)
    importable, blocked = assess_import(candidates, issues, detected_risks)

    print_plan(importable, blocked)

    if args.dry_run:
        return EXIT_OK

    if not importable:
        print('Nothing to apply.')
        return EXIT_OK

    if not args.yes:
        answer = input(f'Apply these {len(importable)} change(s) to {args.project}@{args.branch}? [y/N] ')
        if answer.strip().lower() != 'y':
            print('Aborted.')
            return EXIT_OK

    extra_comment = args.comment.strip()
    failures = 0
    for item in importable:
        comment = f"{item['comment']} — {extra_comment}" if extra_comment else item['comment']
        ok, error = api_post(base_url, token, '/api/v2/sca/issues-releases/change-status', {
            'issueReleaseKey': item['issue_release_key'],
            'transitionKey': item['transition_key'],
            'comment': comment,
        })
        status = 'OK' if ok else f'FAILED ({error})'
        print(f"  {item['vulnerability_id']} / {item['package_url']}: {status}")
        if not ok:
            failures += 1

    return EXIT_PARTIAL_FAILURE if failures else EXIT_OK


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except UsageError as e:
        print(f'error: {e}', file=sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)
    except NetworkError as e:
        print(f'error: {e}', file=sys.stderr)
        sys.exit(EXIT_NETWORK_ERROR)
