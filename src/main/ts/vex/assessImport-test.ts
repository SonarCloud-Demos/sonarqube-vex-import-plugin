import { DetectedRisk } from '../api/scaDetectedRisks';
import { ChangelogEntry } from '../api/scaChangelog';
import { assessImport, ChangelogFetcher } from './assessImport';
import { VexParseResult } from './parseVex';
import { DEFAULT_MAPPING, StatusMapping, withUndecided } from './transitionMapping';

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

const noHistory: ChangelogFetcher = async () => [];

function statusChangeAt(createdAt: string, overrides: Partial<ChangelogEntry> = {}): ChangelogEntry {
  return {
    key: 'change-1',
    createdAt,
    changeData: [{ fieldName: 'status', oldValue: 'OPEN', newValue: 'CONFIRM' }],
    ...overrides,
  };
}

describe('assessImport', () => {
  it('produces an importable plan item for a matching, actionable candidate', async () => {
    const result = await assessImport(vex(), [risk()], noHistory);
    expect(result.blocked).toEqual([]);
    expect(result.conflicts).toEqual([]);
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

  it('appends the VEX contact to the comment when the candidate carries one', async () => {
    const result = await assessImport(
      vex({
        candidates: [
          {
            vulnerabilityId: 'CVE-2024-1111',
            packageUrl: 'pkg:npm/express@4.19.2',
            analysis: { state: 'not_affected', detail: 'safe' },
            vexContact: 'Jane Doe <jane@acme.com>',
          },
        ],
      }),
      [risk()],
      noHistory
    );
    expect(result.importable[0].comment).toBe('safe (VEX contact: Jane Doe <jane@acme.com>)');
  });

  it('blocks a candidate with no matching detected risk', async () => {
    const result = await assessImport(vex(), [], noHistory);
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: 'SonarQube did not detect this dependency on this branch' },
    ]);
  });

  it('blocks a candidate whose transition is not offered by the current status', async () => {
    const result = await assessImport(vex(), [risk({ transitions: ['FIXED'] })], noHistory);
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        reason: 'transition SAFE is not valid from current status OPEN for this risk',
      },
    ]);
  });

  it('blocks a candidate with an unactionable analysis state', async () => {
    const result = await assessImport(
      vex({ candidates: [{ vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'in_triage' } }] }),
      [risk()],
      noHistory
    );
    expect(result.importable).toEqual([]);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: "VEX analysis.state 'in_triage' is not actionable" },
    ]);
  });

  it('carries parser-level issues straight into blocked', async () => {
    const result = await assessImport(
      vex({ candidates: [], issues: [{ vulnerabilityId: 'CVE-2024-2222', reason: 'no affected component reference in VEX entry' }] }),
      [],
      noHistory
    );
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-2222', packageUrl: undefined, reason: 'no affected component reference in VEX entry' },
    ]);
  });

  it('blocks duplicate (CVE, PURL) entries after the first', async () => {
    const dup = { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'not_affected', detail: 'safe' } };
    const result = await assessImport(vex({ candidates: [dup, dup] }), [risk()], noHistory);
    expect(result.importable).toHaveLength(1);
    expect(result.blocked).toEqual([
      { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', reason: 'duplicate VEX entry for this CVE/package — the first occurrence was used' },
    ]);
  });

  describe('conflict detection', () => {
    it('flags a conflict when SonarQube status was changed more recently than the VEX date', async () => {
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'not_affected', detail: 'safe' },
        vexReferenceDate: '2026-01-01T00:00:00Z',
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt('2026-02-01T00:00:00Z', {
        user: { login: 'jdoe' },
        markdownComment: 'confirmed manually',
      })];

      const result = await assessImport(vex({ candidates: [candidate] }), [risk()], fetchChangelog);

      expect(result.importable).toEqual([]);
      expect(result.conflicts).toEqual([
        {
          item: {
            issueReleaseKey: 'key-1',
            vulnerabilityId: 'CVE-2024-1111',
            packageUrl: 'pkg:npm/express@4.19.2',
            currentStatus: 'OPEN',
            transitionKey: 'SAFE',
            comment: 'safe',
          },
          vexReferenceDate: '2026-01-01T00:00:00Z',
          sonarLastChangeDate: '2026-02-01T00:00:00Z',
          sonarLastChangeUser: 'jdoe',
          sonarLastChangeComment: 'confirmed manually',
        },
      ]);
    });

    it('is importable when the VEX date is newer than the SonarQube change', async () => {
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'not_affected', detail: 'safe' },
        vexReferenceDate: '2026-03-01T00:00:00Z',
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt('2026-02-01T00:00:00Z')];

      const result = await assessImport(vex({ candidates: [candidate] }), [risk()], fetchChangelog);

      expect(result.conflicts).toEqual([]);
      expect(result.importable).toHaveLength(1);
    });

    it('treats equal timestamps as no conflict (same-or-newer)', async () => {
      const sameInstant = '2026-02-01T00:00:00Z';
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'not_affected', detail: 'safe' },
        vexReferenceDate: sameInstant,
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt(sameInstant)];

      const result = await assessImport(vex({ candidates: [candidate] }), [risk()], fetchChangelog);

      expect(result.conflicts).toEqual([]);
      expect(result.importable).toHaveLength(1);
    });

    it('is a conflict when the VEX has no reference date at all but SonarQube history exists', async () => {
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'not_affected', detail: 'safe' },
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt('2026-02-01T00:00:00Z')];

      const result = await assessImport(vex({ candidates: [candidate] }), [risk()], fetchChangelog);

      expect(result.importable).toEqual([]);
      expect(result.conflicts).toHaveLength(1);
    });

    it('treats an unparseable VEX date as absent — still a conflict', async () => {
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'not_affected', detail: 'safe' },
        vexReferenceDate: 'not-a-date',
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt('2026-02-01T00:00:00Z')];

      const result = await assessImport(vex({ candidates: [candidate] }), [risk()], fetchChangelog);

      expect(result.conflicts).toHaveLength(1);
    });

    it('is importable when the changelog is empty (never manually transitioned)', async () => {
      const result = await assessImport(vex(), [risk()], async () => []);
      expect(result.conflicts).toEqual([]);
      expect(result.importable).toHaveLength(1);
    });

    it('is importable when the changelog has entries but none touch status', async () => {
      const fetchChangelog: ChangelogFetcher = async () => [
        { key: 'c1', createdAt: '2026-02-01T00:00:00Z', changeData: [{ fieldName: 'severity', oldValue: 'LOW', newValue: 'HIGH' }] },
      ];
      const result = await assessImport(vex(), [risk()], fetchChangelog);
      expect(result.conflicts).toEqual([]);
      expect(result.importable).toHaveLength(1);
    });

    it('blocks the item (not conflict, not importable) when the changelog fetch fails', async () => {
      const fetchChangelog: ChangelogFetcher = async () => {
        throw new Error('network down');
      };
      const result = await assessImport(vex(), [risk()], fetchChangelog);
      expect(result.importable).toEqual([]);
      expect(result.conflicts).toEqual([]);
      expect(result.blocked).toEqual([
        {
          vulnerabilityId: 'CVE-2024-1111',
          packageUrl: 'pkg:npm/express@4.19.2',
          reason: 'could not verify SonarQube status-change history: network down',
        },
      ]);
    });

    it('keeps importable, conflict, and blocked outcomes independent across a mixed batch', async () => {
      const candidates = [
        { vulnerabilityId: 'CVE-1', packageUrl: 'pkg:npm/a@1', analysis: { state: 'not_affected' as const, detail: 'a' } },
        { vulnerabilityId: 'CVE-2', packageUrl: 'pkg:npm/b@1', analysis: { state: 'not_affected' as const, detail: 'b' } },
        { vulnerabilityId: 'CVE-3', packageUrl: 'pkg:npm/c@1', analysis: { state: 'not_affected' as const, detail: 'c' } },
      ];
      const risks = [
        risk({ issueReleaseKey: 'k1', vulnerabilityId: 'CVE-1', packageUrl: 'pkg:npm/a@1' }),
        risk({ issueReleaseKey: 'k2', vulnerabilityId: 'CVE-2', packageUrl: 'pkg:npm/b@1' }),
        risk({ issueReleaseKey: 'k3', vulnerabilityId: 'CVE-3', packageUrl: 'pkg:npm/c@1' }),
      ];
      const fetchChangelog: ChangelogFetcher = async (key) => {
        if (key === 'k1') return []; // clean import
        if (key === 'k2') return [statusChangeAt('2026-01-01T00:00:00Z')]; // conflict (no VEX date)
        throw new Error('boom'); // k3: blocked
      };

      const result = await assessImport(vex({ candidates }), risks, fetchChangelog);

      expect(result.importable.map((i) => i.issueReleaseKey)).toEqual(['k1']);
      expect(result.conflicts.map((c) => c.item.issueReleaseKey)).toEqual(['k2']);
      expect(result.blocked).toHaveLength(1);
      expect(result.blocked[0].vulnerabilityId).toBe('CVE-3');
    });
  });

  describe('adjustable status mapping', () => {
    const undecidedOpen: StatusMapping = withUndecided({ ...DEFAULT_MAPPING }, 'OPEN');
    const inTriage = (detail?: string) =>
      vex({
        candidates: [
          { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', analysis: { state: 'in_triage', detail } },
        ],
      });

    it('keeps v0.1.0 behavior by default: in_triage is blocked', async () => {
      const result = await assessImport(inTriage(), [risk()], noHistory);
      expect(result.importable).toEqual([]);
      expect(result.unchanged).toEqual([]);
      expect(result.blocked).toEqual([
        {
          vulnerabilityId: 'CVE-2024-1111',
          packageUrl: 'pkg:npm/express@4.19.2',
          reason: "VEX analysis.state 'in_triage' is not actionable",
        },
      ]);
    });

    it('reports an already-Open risk as unchanged when undecided maps to Open', async () => {
      const result = await assessImport(inTriage(), [risk({ status: 'OPEN' })], noHistory, undecidedOpen);
      expect(result.importable).toEqual([]);
      expect(result.blocked).toEqual([]);
      expect(result.unchanged).toEqual([
        { vulnerabilityId: 'CVE-2024-1111', packageUrl: 'pkg:npm/express@4.19.2', currentStatus: 'OPEN' },
      ]);
    });

    it.each(['CONFIRM', 'ACCEPT', 'SAFE'])('plans REOPEN for a %s risk when undecided maps to Open', async (status) => {
      const result = await assessImport(
        inTriage('Vendor still investigating'),
        [risk({ status, transitions: ['REOPEN', 'SAFE'] })],
        noHistory,
        undecidedOpen
      );
      expect(result.importable).toEqual([
        {
          issueReleaseKey: 'key-1',
          vulnerabilityId: 'CVE-2024-1111',
          packageUrl: 'pkg:npm/express@4.19.2',
          currentStatus: status,
          transitionKey: 'REOPEN',
          comment: 'Vendor still investigating',
        },
      ]);
    });

    it('blocks reopening when the server does not offer REOPEN for this risk', async () => {
      const result = await assessImport(inTriage(), [risk({ status: 'FIXED', transitions: [] })], noHistory, undecidedOpen);
      expect(result.importable).toEqual([]);
      expect(result.blocked[0].reason).toBe('transition REOPEN is not valid from current status FIXED for this risk');
    });

    it('sends a reopen through the conflict guard like any other change', async () => {
      const candidate = {
        vulnerabilityId: 'CVE-2024-1111',
        packageUrl: 'pkg:npm/express@4.19.2',
        analysis: { state: 'in_triage' },
        vexReferenceDate: '2026-01-01T00:00:00Z',
      };
      const fetchChangelog: ChangelogFetcher = async () => [statusChangeAt('2026-02-01T00:00:00Z')];
      const result = await assessImport(
        vex({ candidates: [candidate] }),
        [risk({ status: 'CONFIRM', transitions: ['REOPEN'] })],
        fetchChangelog,
        undecidedOpen
      );
      expect(result.importable).toEqual([]);
      expect(result.conflicts).toHaveLength(1);
      expect(result.conflicts[0].item.transitionKey).toBe('REOPEN');
    });

    it('does not fetch history for an already-Open risk (nothing to change)', async () => {
      const fetchChangelog = jest.fn(async () => [] as ChangelogEntry[]);
      await assessImport(inTriage(), [risk({ status: 'OPEN' })], fetchChangelog, undecidedOpen);
      expect(fetchChangelog).not.toHaveBeenCalled();
    });

    it('applies a per-row override for a decided state', async () => {
      const mapping: StatusMapping = { ...DEFAULT_MAPPING, not_affected: 'CONFIRM' };
      const result = await assessImport(vex(), [risk()], noHistory, mapping);
      expect(result.importable[0].transitionKey).toBe('CONFIRM');
    });
  });
});
