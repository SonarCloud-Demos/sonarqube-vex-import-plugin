import { BranchInfo } from '../api/projectBranches';

/** The branch (or pull request) the user is browsing in SonarQube when opening the plugin page. */
export interface RequestedBranch {
  branch?: string;
  pullRequest?: string;
}

/**
 * Which branch the user is browsing. SonarQube is expected to pass it to the
 * extension as `branchLike`, but on project extension pages (seen on 2026.5)
 * it doesn't, while the page URL does carry `branch=` / `pullRequest=` — the
 * same parameters SonarQube's own pages and sidebar links use. So: branchLike
 * first, then the URL.
 */
export function requestedBranch(branchLike: { name?: string } | undefined, search: string): RequestedBranch {
  if (branchLike?.name) {
    return { branch: branchLike.name };
  }
  const params = new URLSearchParams(search);
  const pullRequest = params.get('pullRequest') || undefined;
  return pullRequest ? { pullRequest } : { branch: params.get('branch') || undefined };
}

export interface BranchChoice {
  branch?: BranchInfo;
  notice?: string;
}

/**
 * Picks the target branch among the project's long-lived branches:
 * - keep the one already selected in this wizard session (e.g. coming back from the assessment);
 * - else the branch being browsed in SonarQube;
 * - else the main branch, with a notice when the browsed branch or pull request
 *   can't be targeted (VEX import works on long-lived branches only).
 */
export function pickBranch(branches: BranchInfo[], requested: RequestedBranch, current: BranchInfo | null): BranchChoice {
  const main = branches.find((b) => b.isMain) ?? branches[0];
  const fallback = main ? `the main branch (${main.name})` : 'a long-lived branch';

  const kept = current && branches.find((b) => b.name === current.name);
  if (kept) {
    return { branch: kept };
  }

  if (requested.pullRequest) {
    return {
      branch: main,
      notice: `You're browsing pull request ${requested.pullRequest}. VEX import applies to long-lived branches only, so ${fallback} is selected instead.`,
    };
  }

  if (requested.branch) {
    const browsed = branches.find((b) => b.name === requested.branch);
    if (browsed) {
      return { branch: browsed };
    }
    return {
      branch: main,
      notice: `Branch "${requested.branch}" isn't a long-lived branch. VEX import applies to long-lived branches only, so ${fallback} is selected instead.`,
    };
  }

  return { branch: main };
}
