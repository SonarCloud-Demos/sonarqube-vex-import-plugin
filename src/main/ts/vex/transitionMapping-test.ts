import {
  DEFAULT_MAPPING,
  describeMapping,
  isDefaultMapping,
  mapAnalysisToTransition,
  StatusMapping,
  withUndecided,
} from './transitionMapping';

describe('mapAnalysisToTransition', () => {
  it('blocks when analysis is undefined', () => {
    expect(mapAnalysisToTransition(undefined)).toEqual({ blocked: true, stateKey: 'missing', reason: 'VEX entry has no analysis.state' });
  });

  it.each([
    ['not_affected', 'SAFE'],
    ['false_positive', 'SAFE'],
    ['resolved', 'FIXED'],
    ['resolved_with_pedigree', 'FIXED'],
  ] as const)('maps state %s to %s', (state, target) => {
    const result = mapAnalysisToTransition({ state });
    expect(result).toMatchObject({ blocked: false, target });
  });

  it('maps exploitable + will_not_fix response to ACCEPT', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable', response: ['will_not_fix'] });
    expect(result).toMatchObject({ blocked: false, target: 'ACCEPT', stateKey: 'exploitable_will_not_fix' });
  });

  it('maps exploitable without will_not_fix to CONFIRM', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable', response: ['update'] });
    expect(result).toMatchObject({ blocked: false, target: 'CONFIRM', stateKey: 'exploitable' });
  });

  it('maps exploitable with no response to CONFIRM', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable' });
    expect(result).toMatchObject({ blocked: false, target: 'CONFIRM', stateKey: 'exploitable' });
  });

  it('blocks in_triage as not actionable', () => {
    const result = mapAnalysisToTransition({ state: 'in_triage' });
    expect(result).toEqual({ blocked: true, stateKey: 'in_triage', reason: "VEX analysis.state 'in_triage' is not actionable" });
  });

  it('classifies a non-string state as unrecognized, with a printable reason', () => {
    expect(mapAnalysisToTransition({ state: ['in_triage'] as unknown as string })).toEqual({
      blocked: true,
      stateKey: 'unrecognized',
      reason: `VEX analysis.state '["in_triage"]' is not actionable`,
    });
  });

  it('prints a non-string state as compact JSON, like the CLI', () => {
    expect(mapAnalysisToTransition({ state: { x: 1 } as unknown as string })).toMatchObject({
      reason: `VEX analysis.state '{"x":1}' is not actionable`,
    });
  });

  it('counts an empty list state as unrecognized and an empty string as missing, like the CLI', () => {
    expect(mapAnalysisToTransition({ state: [] as unknown as string })).toMatchObject({ stateKey: 'unrecognized' });
    expect(mapAnalysisToTransition({ state: '' })).toMatchObject({ stateKey: 'missing' });
  });

  it('names the exploitable + will_not_fix row when it is mapped to Skip', () => {
    const mapping: StatusMapping = { ...DEFAULT_MAPPING, exploitable_will_not_fix: 'SKIP' };
    expect(mapAnalysisToTransition({ state: 'exploitable', response: ['will_not_fix'] }, mapping)).toMatchObject({
      blocked: true,
      reason: "VEX analysis 'exploitable + will_not_fix' is mapped to Skip",
    });
  });

  it('ignores a non-string detail', () => {
    expect(mapAnalysisToTransition({ state: 'resolved', detail: 42 as unknown as string })).toMatchObject({
      comment: 'VEX import: state=resolved',
    });
  });

  it('blocks an unrecognized state', () => {
    const result = mapAnalysisToTransition({ state: 'made_up' });
    expect(result).toEqual({ blocked: true, stateKey: 'unrecognized', reason: "VEX analysis.state 'made_up' is not actionable" });
  });

  it('uses analysis.detail as the comment when present', () => {
    const result = mapAnalysisToTransition({ state: 'not_affected', detail: '  Not reachable from any entry point.  ' });
    expect(result).toMatchObject({ comment: 'Not reachable from any entry point.' });
  });

  it('generates a fallback comment from state and justification when detail is absent', () => {
    const result = mapAnalysisToTransition({ state: 'not_affected', justification: 'code_not_reachable' });
    expect(result).toMatchObject({ comment: 'VEX import: state=not_affected, justification=code_not_reachable' });
  });

  it('generates a fallback comment without a justification suffix when none is given', () => {
    const result = mapAnalysisToTransition({ state: 'not_affected' });
    expect(result).toMatchObject({ comment: 'VEX import: state=not_affected' });
  });

  describe('with an adjusted mapping', () => {
    const undecidedOpen: StatusMapping = withUndecided({ ...DEFAULT_MAPPING }, 'OPEN');

    it.each([
      [{ state: 'in_triage' }, 'in_triage', 'VEX import: state=in_triage'],
      [{ state: 'made_up' }, 'unrecognized', 'VEX import: state=made_up'],
      [{}, 'missing', 'VEX import: no analysis.state'],
    ] as const)('maps undecided %j to OPEN', (analysis, stateKey, comment) => {
      expect(mapAnalysisToTransition(analysis, undecidedOpen)).toEqual({ blocked: false, target: 'OPEN', stateKey, comment });
    });

    it('maps a missing analysis object to OPEN too', () => {
      expect(mapAnalysisToTransition(undefined, undecidedOpen)).toMatchObject({ blocked: false, target: 'OPEN', stateKey: 'missing' });
    });

    it('keeps the VEX detail as the comment when importing as Open', () => {
      const result = mapAnalysisToTransition({ state: 'in_triage', detail: 'Vendor still investigating' }, undecidedOpen);
      expect(result).toMatchObject({ target: 'OPEN', comment: 'Vendor still investigating' });
    });

    it('applies a per-row override for a decided state', () => {
      const mapping: StatusMapping = { ...DEFAULT_MAPPING, false_positive: 'CONFIRM' };
      expect(mapAnalysisToTransition({ state: 'false_positive' }, mapping)).toMatchObject({ target: 'CONFIRM' });
      expect(mapAnalysisToTransition({ state: 'not_affected' }, mapping)).toMatchObject({ target: 'SAFE' });
    });

    it('blocks a decided state mapped to Skip with a distinct reason', () => {
      const mapping: StatusMapping = { ...DEFAULT_MAPPING, resolved: 'SKIP' };
      expect(mapAnalysisToTransition({ state: 'resolved' }, mapping)).toEqual({
        blocked: true,
        stateKey: 'resolved',
        reason: "VEX analysis 'resolved' is mapped to Skip",
      });
    });

    it('can map undecided states independently', () => {
      const mapping: StatusMapping = { ...DEFAULT_MAPPING, in_triage: 'OPEN' };
      expect(mapAnalysisToTransition({ state: 'in_triage' }, mapping)).toMatchObject({ target: 'OPEN' });
      expect(mapAnalysisToTransition({ state: 'made_up' }, mapping)).toMatchObject({ blocked: true });
    });
  });

  describe('mapping helpers', () => {
    it('recognizes the default mapping', () => {
      expect(isDefaultMapping({ ...DEFAULT_MAPPING })).toBe(true);
      expect(isDefaultMapping(withUndecided({ ...DEFAULT_MAPPING }, 'OPEN'))).toBe(false);
      expect(isDefaultMapping(withUndecided(withUndecided({ ...DEFAULT_MAPPING }, 'OPEN'), 'SKIP'))).toBe(true);
    });

    it('describes only the rows that differ from the default', () => {
      expect(describeMapping({ ...DEFAULT_MAPPING })).toBe('default');
      expect(describeMapping({ ...DEFAULT_MAPPING, in_triage: 'OPEN', false_positive: 'CONFIRM' })).toBe(
        'false_positive → Confirmed, in_triage → Open'
      );
    });

    it('does not mutate the mapping it is given', () => {
      const base = { ...DEFAULT_MAPPING };
      withUndecided(base, 'OPEN');
      expect(base).toEqual(DEFAULT_MAPPING);
    });
  });
});
