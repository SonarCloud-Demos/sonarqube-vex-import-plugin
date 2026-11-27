import { CycloneDxAnalysis } from './types';

/** A SonarQube dependency-risk workflow transition this plugin may send. */
export type TransitionKey = 'SAFE' | 'FIXED' | 'ACCEPT' | 'CONFIRM' | 'REOPEN';

/**
 * What a VEX analysis state is mapped to. `SKIP` means "do not import, report it".
 *
 * `OPEN` means "the risk must still be dealt with" (see assessImport.ts):
 * - risk already OPEN or CONFIRMed -> no change. Confirmed already says "real,
 *   to be fixed", and an undecided VEX statement adds nothing to that decision,
 *   so it is never demoted back to Open;
 * - risk ACCEPTed, SAFE or FIXED -> the REOPEN transition, and always through
 *   the conflict step when the risk has status-change history, so a decision
 *   made in SonarQube is never overridden without the user confirming it.
 */
export type MappingTarget = 'SAFE' | 'FIXED' | 'ACCEPT' | 'CONFIRM' | 'OPEN' | 'SKIP';

/** The VEX analysis states (and state + condition pairs) a mapping row exists for. */
export type VexStateKey =
  | 'not_affected'
  | 'false_positive'
  | 'resolved'
  | 'resolved_with_pedigree'
  | 'exploitable'
  | 'exploitable_will_not_fix'
  | 'in_triage'
  | 'missing'
  | 'unrecognized';

export type StatusMapping = Record<VexStateKey, MappingTarget>;

export const VEX_STATE_KEYS: readonly VexStateKey[] = [
  'not_affected',
  'false_positive',
  'resolved',
  'resolved_with_pedigree',
  'exploitable',
  'exploitable_will_not_fix',
  'in_triage',
  'missing',
  'unrecognized',
];

/** The states with no decision in them: an analysis is pending, absent, or not a CycloneDX value. */
export const UNDECIDED_STATE_KEYS: readonly VexStateKey[] = ['in_triage', 'missing', 'unrecognized'];

export const MAPPING_TARGETS: readonly MappingTarget[] = ['SAFE', 'FIXED', 'ACCEPT', 'CONFIRM', 'OPEN', 'SKIP'];

// KEEP IN SYNC WITH cli/vex-import.py (DEFAULT_MAPPING) and SPEC.md §3.3
export const DEFAULT_MAPPING: Readonly<StatusMapping> = Object.freeze({
  not_affected: 'SAFE',
  false_positive: 'SAFE',
  resolved: 'FIXED',
  resolved_with_pedigree: 'FIXED',
  exploitable: 'CONFIRM',
  exploitable_will_not_fix: 'ACCEPT',
  in_triage: 'SKIP',
  missing: 'SKIP',
  unrecognized: 'SKIP',
});

export function isDefaultMapping(mapping: StatusMapping): boolean {
  return VEX_STATE_KEYS.every((key) => mapping[key] === DEFAULT_MAPPING[key]);
}

/** Returns a copy of `mapping` with every undecided state set to `target`. */
export function withUndecided(mapping: StatusMapping, target: 'OPEN' | 'SKIP'): StatusMapping {
  const next = { ...mapping };
  for (const key of UNDECIDED_STATE_KEYS) {
    next[key] = target;
  }
  return next;
}

export type MappingResult =
  | { blocked: false; target: Exclude<MappingTarget, 'SKIP'>; stateKey: VexStateKey; comment: string }
  | { blocked: true; stateKey: VexStateKey; reason: string };

const KNOWN_STATES = new Set(['not_affected', 'false_positive', 'resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage']);

export function stateKeyFor(analysis: CycloneDxAnalysis | undefined): VexStateKey {
  const state = analysis?.state;
  if (!state) {
    return 'missing';
  }
  if (typeof state !== 'string' || !KNOWN_STATES.has(state)) {
    return 'unrecognized';
  }
  if (state === 'exploitable') {
    return (analysis?.response ?? []).includes('will_not_fix') ? 'exploitable_will_not_fix' : 'exploitable';
  }
  return state as VexStateKey;
}

function buildComment(analysis: CycloneDxAnalysis | undefined): string {
  const detail = typeof analysis?.detail === 'string' ? analysis.detail.trim() : '';
  if (detail) {
    return detail;
  }
  if (!analysis?.state) {
    return 'VEX import: no analysis.state';
  }
  const justificationSuffix = analysis.justification ? `, justification=${analysis.justification}` : '';
  return `VEX import: state=${analysis.state}${justificationSuffix}`;
}

/** The raw state as written in the file, printable even when it isn't a string. KEEP IN SYNC WITH cli/vex-import.py (_printable_state) */
function printableState(state: unknown): string {
  return typeof state === 'string' ? state : JSON.stringify(state);
}

function skipReason(analysis: CycloneDxAnalysis | undefined, stateKey: VexStateKey): string {
  if (DEFAULT_MAPPING[stateKey] === 'SKIP') {
    // Same wording as v0.1.0 so the default plan stays identical.
    return stateKey === 'missing'
      ? 'VEX entry has no analysis.state'
      : `VEX analysis.state '${printableState(analysis?.state)}' is not actionable`;
  }
  return `VEX analysis '${STATE_LABELS[stateKey]}' is mapped to Skip`;
}

/**
 * Maps a VEX vulnerability's analysis to a target SonarQube status, using the
 * given (user-adjustable) mapping, plus the comment that will be sent with it.
 * Returns `blocked: true` when the row's target is Skip.
 */
export function mapAnalysisToTransition(
  analysis: CycloneDxAnalysis | undefined,
  mapping: StatusMapping = DEFAULT_MAPPING
): MappingResult {
  const stateKey = stateKeyFor(analysis);
  const target = mapping[stateKey];
  if (target === 'SKIP') {
    return { blocked: true, stateKey, reason: skipReason(analysis, stateKey) };
  }
  return { blocked: false, target, stateKey, comment: buildComment(analysis) };
}

export const TARGET_LABELS: Readonly<Record<MappingTarget, string>> = {
  SAFE: 'Safe',
  FIXED: 'Fixed',
  ACCEPT: 'Accepted',
  CONFIRM: 'Confirmed',
  OPEN: 'Open',
  SKIP: 'Skip (not importable)',
};

export const STATE_LABELS: Readonly<Record<VexStateKey, string>> = {
  not_affected: 'not_affected',
  false_positive: 'false_positive',
  resolved: 'resolved',
  resolved_with_pedigree: 'resolved_with_pedigree',
  exploitable: 'exploitable (otherwise)',
  exploitable_will_not_fix: 'exploitable + will_not_fix',
  in_triage: 'in_triage',
  missing: 'missing analysis.state',
  unrecognized: 'unrecognized analysis.state',
};

/** Human-readable list of the rows that differ from the default mapping, or 'default'. */
export function describeMapping(mapping: StatusMapping): string {
  const changed = VEX_STATE_KEYS.filter((key) => mapping[key] !== DEFAULT_MAPPING[key]);
  if (changed.length === 0) {
    return 'default';
  }
  return changed.map((key) => `${STATE_LABELS[key]} → ${TARGET_LABELS[mapping[key]]}`).join(', ');
}
