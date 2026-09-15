export interface BranchInfo {
  name: string;
  isMain: boolean;
  excludedFromPurge: boolean;
  type?: string;
}

/**
 * Returns all long-lived branches for a project (excludedFromPurge = true).
 * Includes the main branch, which is always excludedFromPurge.
 */
export async function fetchLongLivedBranches(projectKey: string): Promise<BranchInfo[]> {
  const res = await fetch(
    `/api/project_branches/list?project=${encodeURIComponent(projectKey)}`,
    { credentials: 'same-origin' }
  );
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(
      `api/project_branches/list failed: HTTP ${res.status}${text ? ' — ' + text : ''}`
    );
  }
  const data = (await res.json()) as { branches: BranchInfo[] };
  return (data.branches ?? []).filter((b) => b.excludedFromPurge);
}
