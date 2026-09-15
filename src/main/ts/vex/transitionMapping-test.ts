import { mapAnalysisToTransition } from './transitionMapping';

describe('mapAnalysisToTransition', () => {
  it('blocks when analysis is undefined', () => {
    expect(mapAnalysisToTransition(undefined)).toEqual({ blocked: true, reason: 'VEX entry has no analysis.state' });
  });

  it.each([
    ['not_affected', 'SAFE'],
    ['false_positive', 'SAFE'],
    ['resolved', 'FIXED'],
    ['resolved_with_pedigree', 'FIXED'],
  ] as const)('maps state %s to %s', (state, transitionKey) => {
    const result = mapAnalysisToTransition({ state });
    expect(result).toMatchObject({ blocked: false, transitionKey });
  });

  it('maps exploitable + will_not_fix response to ACCEPT', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable', response: ['will_not_fix'] });
    expect(result).toMatchObject({ blocked: false, transitionKey: 'ACCEPT' });
  });

  it('maps exploitable without will_not_fix to CONFIRM', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable', response: ['update'] });
    expect(result).toMatchObject({ blocked: false, transitionKey: 'CONFIRM' });
  });

  it('maps exploitable with no response to CONFIRM', () => {
    const result = mapAnalysisToTransition({ state: 'exploitable' });
    expect(result).toMatchObject({ blocked: false, transitionKey: 'CONFIRM' });
  });

  it('blocks in_triage as not actionable', () => {
    const result = mapAnalysisToTransition({ state: 'in_triage' });
    expect(result).toEqual({ blocked: true, reason: "VEX analysis.state 'in_triage' is not actionable" });
  });

  it('blocks an unrecognized state', () => {
    const result = mapAnalysisToTransition({ state: 'made_up' });
    expect(result).toEqual({ blocked: true, reason: "VEX analysis.state 'made_up' is not actionable" });
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
});
