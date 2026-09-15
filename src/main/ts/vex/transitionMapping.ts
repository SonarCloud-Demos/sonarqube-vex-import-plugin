import { CycloneDxAnalysis } from './types';

export type TransitionKey = 'SAFE' | 'FIXED' | 'ACCEPT' | 'CONFIRM';

export type MappingResult =
  | { blocked: false; transitionKey: TransitionKey; comment: string }
  | { blocked: true; reason: string };

// KEEP IN SYNC WITH cli/vex-import.py (mapAnalysisToTransition / MAPPING_TABLE)
function transitionKeyFor(analysis: CycloneDxAnalysis): TransitionKey | undefined {
  switch (analysis.state) {
    case 'not_affected':
    case 'false_positive':
      return 'SAFE';
    case 'resolved':
    case 'resolved_with_pedigree':
      return 'FIXED';
    case 'exploitable':
      return (analysis.response ?? []).includes('will_not_fix') ? 'ACCEPT' : 'CONFIRM';
    default:
      return undefined;
  }
}

function buildComment(analysis: CycloneDxAnalysis): string {
  const detail = analysis.detail?.trim();
  if (detail) {
    return detail;
  }
  const justificationSuffix = analysis.justification ? `, justification=${analysis.justification}` : '';
  return `VEX import: state=${analysis.state}${justificationSuffix}`;
}

/**
 * Maps a VEX vulnerability's analysis to a SonarQube dependency-risk transitionKey
 * plus the comment that will be sent with it. Returns `blocked: true` when the
 * analysis state isn't actionable (missing, unrecognized, or "in_triage" — undecided).
 */
export function mapAnalysisToTransition(analysis: CycloneDxAnalysis | undefined): MappingResult {
  if (!analysis?.state) {
    return { blocked: true, reason: 'VEX entry has no analysis.state' };
  }

  const transitionKey = transitionKeyFor(analysis);
  if (!transitionKey) {
    return { blocked: true, reason: `VEX analysis.state '${analysis.state}' is not actionable` };
  }

  return { blocked: false, transitionKey, comment: buildComment(analysis) };
}
