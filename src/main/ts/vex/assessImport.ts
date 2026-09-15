import { DetectedRisk } from '../api/scaDetectedRisks';
import { mapAnalysisToTransition, TransitionKey } from './transitionMapping';
import { VexParseResult } from './parseVex';

export interface PlanItem {
  issueReleaseKey: string;
  vulnerabilityId: string;
  packageUrl: string;
  currentStatus: string;
  transitionKey: TransitionKey;
  comment: string;
}

export interface BlockedItem {
  vulnerabilityId?: string;
  packageUrl?: string;
  reason: string;
}

export interface AssessmentResult {
  importable: PlanItem[];
  blocked: BlockedItem[];
}

function matchKey(vulnerabilityId: string, packageUrl: string): string {
  return `${vulnerabilityId}|${packageUrl}`;
}

/**
 * Matches parsed VEX candidates against SonarQube's currently detected
 * dependency risks, producing the plan of importable status changes and the
 * list of VEX entries that cannot be imported, each with a human-readable
 * reason.
 */
export function assessImport(vex: VexParseResult, detected: DetectedRisk[]): AssessmentResult {
  const blocked: BlockedItem[] = vex.issues.map((issue) => ({
    vulnerabilityId: issue.vulnerabilityId,
    packageUrl: issue.packageUrl,
    reason: issue.reason,
  }));

  const detectedByKey = new Map<string, DetectedRisk>();
  for (const risk of detected) {
    if (risk.vulnerabilityId && risk.packageUrl) {
      detectedByKey.set(matchKey(risk.vulnerabilityId, risk.packageUrl), risk);
    }
  }

  const importable: PlanItem[] = [];
  const seen = new Set<string>();

  for (const candidate of vex.candidates) {
    const key = matchKey(candidate.vulnerabilityId, candidate.packageUrl);

    if (seen.has(key)) {
      blocked.push({
        vulnerabilityId: candidate.vulnerabilityId,
        packageUrl: candidate.packageUrl,
        reason: 'duplicate VEX entry for this CVE/package — the first occurrence was used',
      });
      continue;
    }
    seen.add(key);

    const risk = detectedByKey.get(key);
    if (!risk) {
      blocked.push({
        vulnerabilityId: candidate.vulnerabilityId,
        packageUrl: candidate.packageUrl,
        reason: 'SonarQube did not detect this dependency on this branch',
      });
      continue;
    }

    const mapping = mapAnalysisToTransition(candidate.analysis);
    if (mapping.blocked) {
      blocked.push({
        vulnerabilityId: candidate.vulnerabilityId,
        packageUrl: candidate.packageUrl,
        reason: mapping.reason,
      });
      continue;
    }

    if (!risk.transitions.includes(mapping.transitionKey)) {
      blocked.push({
        vulnerabilityId: candidate.vulnerabilityId,
        packageUrl: candidate.packageUrl,
        reason: `transition ${mapping.transitionKey} is not valid from current status ${risk.status} for this risk`,
      });
      continue;
    }

    importable.push({
      issueReleaseKey: risk.issueReleaseKey,
      vulnerabilityId: candidate.vulnerabilityId,
      packageUrl: candidate.packageUrl,
      currentStatus: risk.status,
      transitionKey: mapping.transitionKey,
      comment: mapping.comment,
    });
  }

  return { importable, blocked };
}
