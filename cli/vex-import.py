#!/usr/bin/env python3
"""Import a CycloneDX 1.6 VEX file into SonarQube dependency-risk statuses.

Mirrors the VEX Import wizard's matching/mapping logic (see
src/main/ts/vex/parseVex.ts, transitionMapping.ts, assessImport.ts,
src/main/ts/api/scaChangelog.ts) for use from a script or CI pipeline. Only
dependencies SonarQube has actually detected on the target project branch can
be affected.

Usage:
    python3 vex-import.py \\
        --base-url https://sonarqube.example.com \\
        --project my-project \\
        --branch main \\
        --vex-file report.vex.json \\
        --token <your-sonarqube-token> \\
        [--conflict-resolution keep|apply|ask] \\
        [--dry-run] [-y]

This script never contains or stores a token — you provide your own, either
via --token or the SONAR_TOKEN environment variable (the latter is preferred
if you're worried about the token showing up in shell history or process
listings on a shared machine).

--conflict-resolution controls what happens when a VEX entry would change a
risk whose status SonarQube shows was already changed manually more recently
than the VEX's own reference date (or the VEX carries no date to compare):
'ask' (default) prints both sides and prompts per conflict; 'keep' leaves
every conflicting risk as-is; 'apply' applies the VEX's status to all of
them, no prompting — for CI/scripted use. Never prompts during --dry-run.

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
from datetime import datetime

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
    vulnerability_id, package_url, analysis, vex_reference_date. issues: list
    of dicts with vulnerability_id, package_url, reason — per-entry problems
    that don't block the rest of the file."""
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

    metadata = doc.get('metadata') or {}
    document_timestamp = metadata.get('timestamp')
    document_contact = build_document_contact(metadata)

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

        analysis = vuln.get('analysis') or {}
        vex_reference_date = analysis.get('lastUpdated') or analysis.get('firstIssued') or document_timestamp

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
            candidates.append({
                'vulnerability_id': vuln_id,
                'package_url': package_url,
                'analysis': vuln.get('analysis'),
                'vex_reference_date': vex_reference_date,
                'vex_contact': document_contact,
            })

    return candidates, issues


def format_contact(contact):
    name = (contact or {}).get('name')
    email = (contact or {}).get('email')
    if name and email:
        return f'{name} <{email}>'
    return name or email or (contact or {}).get('phone') or None


def build_document_contact(metadata):
    """Who to contact about this VEX statement, from metadata.authors and/or
    metadata.supplier — None when neither is present."""
    parts = []

    for author in metadata.get('authors') or []:
        formatted = format_contact(author)
        if formatted:
            parts.append(formatted)

    supplier = metadata.get('supplier') or {}
    if supplier.get('name'):
        parts.append(supplier['name'])
    for contact in supplier.get('contact') or []:
        formatted = format_contact(contact)
        if formatted:
            parts.append(formatted)

    return ', '.join(parts) if parts else None


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


# --- Changelog / last-status-change lookup ------------------------------------
# KEEP IN SYNC WITH src/main/ts/api/scaChangelog.ts

def fetch_issue_release_changelog(base_url, token, issue_release_key):
    raw = api_get(base_url, token, f'/api/v2/sca/issues-releases/{issue_release_key}/changelogs')
    return raw.get('changelog') or raw.get('items') or []


def find_last_status_change(changelog):
    """Returns a dict {created_at, user_login, user_name, comment} for the most
    recent entry that changed the risk's status, or None if it was never
    manually transitioned."""
    status_entries = [
        entry for entry in changelog
        if any(change.get('fieldName') == 'status' for change in (entry.get('changeData') or []))
    ]
    if not status_entries:
        return None

    latest = max(status_entries, key=lambda e: e.get('createdAt') or '')
    user = latest.get('user') or {}
    return {
        'created_at': latest.get('createdAt'),
        'user_login': user.get('login'),
        'user_name': user.get('name'),
        'comment': latest.get('markdownComment'),
    }


def parse_date_safe(iso):
    """Returns a comparable datetime, or None if iso is missing/unparseable."""
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError):
        return None


# --- Matching against SonarQube's detected risks ------------------------------
# KEEP IN SYNC WITH src/main/ts/vex/assessImport.ts

def assess_import(candidates, issues, detected_risks, fetch_changelog):
    """detected_risks: list of dicts with issue_release_key, vulnerability_id,
    package_url, status, transitions. fetch_changelog: callable
    issue_release_key -> list[dict] (the raw changelog entries).
    Returns (importable, blocked, conflicts)."""
    blocked = [dict(i) for i in issues]

    detected_by_key = {}
    for risk in detected_risks:
        if risk.get('vulnerability_id') and risk.get('package_url'):
            detected_by_key[(risk['vulnerability_id'], risk['package_url'])] = risk

    # Phase 1: synchronous matching, identical to before except a would-be
    # importable item becomes "provisional" pending the changelog check below.
    provisional = []
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

        vex_contact = candidate.get('vex_contact')
        if vex_contact:
            comment = f'{comment} (VEX contact: {vex_contact})'

        provisional.append({
            'item': {
                'issue_release_key': risk['issue_release_key'],
                'vulnerability_id': candidate['vulnerability_id'],
                'package_url': candidate['package_url'],
                'current_status': risk['status'],
                'transition_key': transition_key,
                'comment': comment,
            },
            'vex_reference_date': candidate.get('vex_reference_date'),
        })

    # Phase 2: sequential (stdlib-only, matches this script's existing
    # fully-sequential apply loop) changelog check per provisional item.
    importable = []
    conflicts = []

    for p in provisional:
        item = p['item']
        try:
            changelog = fetch_changelog(item['issue_release_key'])
        except NetworkError as e:
            blocked.append({
                'vulnerability_id': item['vulnerability_id'],
                'package_url': item['package_url'],
                'reason': f'could not verify SonarQube status-change history: {e}',
            })
            continue

        last_status_change = find_last_status_change(changelog)
        if last_status_change is None:
            importable.append(item)
            continue

        sonar_date = parse_date_safe(last_status_change['created_at'])
        vex_date = parse_date_safe(p['vex_reference_date'])
        vex_is_same_or_newer = vex_date is not None and sonar_date is not None and vex_date >= sonar_date

        if vex_is_same_or_newer:
            importable.append(item)
            continue

        conflicts.append({
            'item': item,
            'vex_reference_date': p['vex_reference_date'],
            'sonar_last_change_date': last_status_change['created_at'],
            'sonar_last_change_user': last_status_change['user_login'] or last_status_change['user_name'],
            'sonar_last_change_comment': last_status_change['comment'],
        })

    return importable, blocked, conflicts


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


def print_plan(importable, blocked, conflicts):
    print(f'\nImportable changes ({len(importable)}):')
    for item in importable:
        print(f"  {item['vulnerability_id']} / {item['package_url']}: {item['current_status']} -> {item['transition_key']}  ({item['comment']})")
    print(f'\nConflicts — need resolution ({len(conflicts)}):')
    for c in conflicts:
        item = c['item']
        who = f" by {c['sonar_last_change_user']}" if c['sonar_last_change_user'] else ''
        print(f"  {item['vulnerability_id']} / {item['package_url']}:")
        print(f"    SonarQube: {item['current_status']}, last changed {c['sonar_last_change_date']}{who} — {c['sonar_last_change_comment'] or '(no comment)'}")
        print(f"    VEX proposes: {item['transition_key']}, reference date {c['vex_reference_date'] or '(none)'} — {item['comment']}")
    print(f'\nNot importable ({len(blocked)}):')
    for item in blocked:
        print(f"  {item.get('vulnerability_id') or '—'} / {item.get('package_url') or '—'}: {item['reason']}")
    print()


def resolve_conflicts(conflicts, mode):
    """Returns the list of conflict items to apply, given --conflict-resolution
    mode. Never prompts for 'keep'/'apply' (non-interactive by design, for
    CI/scripted use); 'ask' prompts once per conflict."""
    if mode == 'keep':
        return []
    if mode == 'apply':
        return [c['item'] for c in conflicts]

    to_apply = []
    for c in conflicts:
        item = c['item']
        who = f" by {c['sonar_last_change_user']}" if c['sonar_last_change_user'] else ''
        print(f"\nConflict: {item['vulnerability_id']} / {item['package_url']}")
        print(f"  SonarQube: {item['current_status']}, last changed {c['sonar_last_change_date']}{who} — {c['sonar_last_change_comment'] or '(no comment)'}")
        print(f"  VEX proposes: {item['transition_key']}, reference date {c['vex_reference_date'] or '(none)'} — {item['comment']}")
        answer = input('  Apply the VEX status despite this conflict? [y/N] ')
        if answer.strip().lower() == 'y':
            to_apply.append(item)
    return to_apply


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base-url', required=True, help='SonarQube base URL, e.g. https://sonarqube.example.com')
    parser.add_argument('--project', required=True, help='Project key')
    parser.add_argument('--branch', required=True, help='Target branch name (no default — must be explicit)')
    parser.add_argument('--vex-file', required=True, help='Path to the CycloneDX 1.6 VEX JSON file')
    parser.add_argument('--token', default=None, help='SonarQube user token. Prefer the SONAR_TOKEN environment variable over this flag if you want to avoid the token appearing in shell history or process listings. This script never embeds or stores a token itself.')
    parser.add_argument('--comment', default='', help='Optional comment appended to every imported item, in addition to the justification imported from the VEX file')
    parser.add_argument('--conflict-resolution', choices=['keep', 'apply', 'ask'], default='ask',
                         help="How to handle a VEX entry that conflicts with a status SonarQube shows was already changed manually more recently: 'ask' (default, interactive prompt per conflict), 'keep' (never apply), 'apply' (always apply, no prompting — for CI)")
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
    importable, blocked, conflicts = assess_import(
        candidates, issues, detected_risks,
        lambda key: fetch_issue_release_changelog(base_url, token, key)
    )

    print_plan(importable, blocked, conflicts)

    if args.dry_run:
        return EXIT_OK

    to_apply = importable + resolve_conflicts(conflicts, args.conflict_resolution)

    if not to_apply:
        print('Nothing to apply.')
        return EXIT_OK

    if not args.yes:
        answer = input(f'Apply these {len(to_apply)} change(s) to {args.project}@{args.branch}? [y/N] ')
        if answer.strip().lower() != 'y':
            print('Aborted.')
            return EXIT_OK

    extra_comment = args.comment.strip()
    failures = 0
    for item in to_apply:
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
