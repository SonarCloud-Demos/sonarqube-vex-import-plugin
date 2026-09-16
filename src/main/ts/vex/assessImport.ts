import { DetectedRisk } from '../api/scaDetectedRisks';
import { ChangelogEntry, findLastStatusChange } from '../api/scaChangelog';
import { concurrentMap } from '../utils/concurrentMap';
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

export interface ConflictItem {
  item: PlanItem;
  vexReferenceDate?: string;
  sonarLastChangeDate: string;
  sonarLastChangeUser?: string;
  sonarLastChangeComment?: string;
}

export interface AssessmentResult {
  importable: PlanItem[];
  blocked: BlockedItem[];
  conflicts: ConflictItem[];
}

export type ChangelogFetcher = (issueReleaseKey: string) => Promise<ChangelogEntry[]>;

interface Provisional {
  item: PlanItem;
  vexReferenceDate?: string;
}

function matchKey(vulnerabilityId: string, packageUrl: string): string {
  return `${vulnerabilityId}|${packageUrl}`;
}

function parseDateSafe(iso: string | undefined): Date | undefined {
  if (!iso) return undefined;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * Matches parsed VEX candidates against SonarQube's currently detected
 * dependency risks, producing the plan of importable status changes, the
 * list of VEX entries that cannot be imported (each with a human-readable
 * reason), and the list of conflicts — candidates that would otherwise be
 * importable, but whose risk was manually transitioned in SonarQube more
 * recently than the VEX's own reference date (or has history and the VEX
 * carries no date to compare against).
 *
 * `fetchChangelog` is required and explicit (no default pointing at the real
 * network fetch) so this stays a pure, network-free function to unit test —
 * callers pass the real src/main/ts/api/scaChangelog.ts fetch in production.
 */
export async function assessImport(
  vex: VexParseResult,
  detected: DetectedRisk[],
  fetchChangelog: ChangelogFetcher
): Promise<AssessmentResult> {
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

  // Phase 1 — synchronous matching, exactly as before, except a would-be
  // importable item goes into `provisional` (network check pending) instead
  // of straight into `importable`.
  const provisional: Provisional[] = [];
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

    provisional.push({
      item: {
        issueReleaseKey: risk.issueReleaseKey,
        vulnerabilityId: candidate.vulnerabilityId,
        packageUrl: candidate.packageUrl,
        currentStatus: risk.status,
        transitionKey: mapping.transitionKey,
        comment: mapping.comment,
      },
      vexReferenceDate: candidate.vexReferenceDate,
    });
  }

  // Phase 2 — for each provisional item, check SonarQube's own change history
  // for a conflict before finalizing it as importable.
  const importable: PlanItem[] = [];
  const conflicts: ConflictItem[] = [];

  await concurrentMap(provisional, 5, async (p): Promise<void> => {
    let changelog: ChangelogEntry[];
    try {
      changelog = await fetchChangelog(p.item.issueReleaseKey);
    } catch (e) {
      blocked.push({
        vulnerabilityId: p.item.vulnerabilityId,
        packageUrl: p.item.packageUrl,
        reason: `could not verify SonarQube status-change history: ${e instanceof Error ? e.message : String(e)}`,
      });
      return;
    }

    const lastStatusChange = findLastStatusChange(changelog);
    if (!lastStatusChange) {
      importable.push(p.item);
      return;
    }

    const sonarDate = parseDateSafe(lastStatusChange.createdAt);
    const vexDate = parseDateSafe(p.vexReferenceDate);
    const vexIsSameOrNewer = vexDate && sonarDate && vexDate.getTime() >= sonarDate.getTime();

    if (vexIsSameOrNewer) {
      importable.push(p.item);
      return;
    }

    conflicts.push({
      item: p.item,
      vexReferenceDate: p.vexReferenceDate,
      sonarLastChangeDate: lastStatusChange.createdAt,
      sonarLastChangeUser: lastStatusChange.userLogin ?? lastStatusChange.userName,
      sonarLastChangeComment: lastStatusChange.comment,
    });
  });

  return { importable, blocked, conflicts };
}
