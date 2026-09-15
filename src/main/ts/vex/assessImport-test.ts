import { DetectedRisk } from '../api/scaDetectedRisks';
import { assessImport } from './assessImport';
import { VexParseResult } from './parseVex';

function risk(overrides: Partial<DetectedRisk> = {}): DetectedRisk {
  return {
    issueReleaseKey: 'key-1',
    projectKey: 'proj',
    branchKey: 'main',
    vulnerabilityId: 'CVE-2024-1111',
    packageUrl: 'pkg:npm/express@4.19.2',
    status: 'OPEN',
    transitions: ['ACCEPT', 'CONFIRM', 'SAFE'],
    ...overrides,
  };
}

function vex(overrides: Partial<VexParseResult> = {}): VexParseResult {
  return {
    candidates: [
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'not_affected', detail: 'safe' } },
    ],
    issues: [],
    ...overrides,
  };
}

describe('assessImport', () => {
  it('produces an importable plan item for a matching, actionable candidate', () => {
    const result = assessImport(vex(), [risk()]);
    expect(result.blocked).toEqual([]);
    expect(result.importable).toEqual([
      {
        issueReleaseKey: 'key-1',
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        currentStatus: 'OPEN',
        transitionKey: 'SAFE',
        comment: 'safe',
      },
    ]);
  });

  it('blocks a candidate with no matching detected risk', () => {
    const result = assessImport(vex(), []);
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: 'SonarQube did not detect this dependency on this branch' },
    ]);
  });

  it('blocks a candidate whose transition is not offered by the current status', () => {
    const result = assessImport(vex(), [risk({ transitions: ['FIXED'] })]);
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        reason: 'transition SAFE is not valid from current status OPEN for this risk',
      },
    ]);
  });

  it('blocks a candidate with an unactionable analysis state', () => {
    const result = assessImport(
      vex({ candidates: [{ vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'in_triage' } }] }),
      [risk()]
    );
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: "VEX analysis.state 'in_triage' is not actionable" },
    ]);
  });

  it('carries parser-level issues straight into blocked', () => {
    const result = assessImport(vex({ candidates: [], issues: [{ vulnerabilityId: 'CVE-2024-2222', reason: 'no affected component reference in VEX entry' }] }), []);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-2222', packageUrl: undefined, reason: 'no affected component reference in VEX entry' },
    ]);
  });

  it('blocks duplicate (CVE, PURL) entries after the first', () => {
    const dup = { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'not_affected', detail: 'safe' } };
    const result = assessImport(vex({ candidates: [dup, dup] }), [risk()]);
    expect(result.importable).toHaveLength(1);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: 'duplicate VEX entry for this CVE/package — the first occurrence was used' },
    ]);
  });
});
