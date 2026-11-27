import { BranchInfo } from '../api/projectBranches';
import { pickBranch, requestedBranch } from './requestedBranch';

const main: BranchInfo = { name: 'main', isMain: true, excludedFromPurge: true };
const release: BranchInfo = { name: 'release-1.0', isMain: false, excludedFromPurge: true };
const branches = [main, release];

describe('requestedBranch', () => {
  it('prefers the branchLike SonarQube passes, when there is one', () => {
    expect(requestedBranch({ name: 'release-1.0' }, '?id=p&branch=main')).toEqual({ branch: 'release-1.0' });
  });

  it('falls back to the branch in the page URL', () => {
    expect(requestedBranch(undefined, '?id=vex-import-smoke-test&branch=release-1.0&qualifier=TRK')).toEqual({ branch: 'release-1.0' });
  });

  it('reports a pull request from the URL', () => {
    expect(requestedBranch(undefined, '?id=p&pullRequest=42')).toEqual({ pullRequest: '42' });
  });

  it('is empty when nothing is browsed', () => {
    expect(requestedBranch(undefined, '?id=p')).toEqual({ branch: undefined });
    expect(requestedBranch(undefined, '')).toEqual({ branch: undefined });
  });
});

describe('pickBranch', () => {
  it('selects the browsed long-lived branch', () => {
    expect(pickBranch(branches, { branch: 'release-1.0' }, null)).toEqual({ branch: release });
  });

  it('selects main when nothing is browsed', () => {
    expect(pickBranch(branches, {}, null)).toEqual({ branch: main });
  });

  it('falls back to main with a notice for a branch that is not long-lived', () => {
    const choice = pickBranch(branches, { branch: 'feature/x' }, null);
    expect(choice.branch).toBe(main);
    expect(choice.notice).toBe(
      'Branch "feature/x" isn\'t a long-lived branch. VEX import applies to long-lived branches only, so the main branch (main) is selected instead.'
    );
  });

  it('falls back to main with a notice for a pull request', () => {
    const choice = pickBranch(branches, { pullRequest: '42' }, null);
    expect(choice.branch).toBe(main);
    expect(choice.notice).toMatch(/^You're browsing pull request 42\. VEX import applies to long-lived branches only/);
  });

  it('keeps the branch already chosen in this wizard session', () => {
    expect(pickBranch(branches, { branch: 'main' }, release)).toEqual({ branch: release });
  });

  it('ignores a previous choice that no longer exists', () => {
    const gone: BranchInfo = { name: 'old', isMain: false, excludedFromPurge: false };
    expect(pickBranch(branches, { branch: 'release-1.0' }, gone)).toEqual({ branch: release });
  });
});
