export interface ChangelogChangeData {
  fieldName: string;
  oldValue?: string;
  newValue?: string;
}

export interface ChangelogUser {
  login?: string;
  name?: string;
}

export interface ChangelogEntry {
  key: string;
  createdAt: string;
  user?: ChangelogUser;
  markdownComment?: string;
  htmlComment?: string;
  changeData?: ChangelogChangeData[];
  actions?: unknown[];
}

export interface LastStatusChange {
  createdAt: string;
  userLogin?: string;
  userName?: string;
  comment?: string;
}

interface ChangelogPage {
  // Only { changelog: [...] } has been observed live (no pagination envelope) —
  // the alternate keys are defensive, mirroring the same tolerance pattern used
  // in scaDetectedRisks.ts for an endpoint whose exact contract wasn't fully
  // nailed down in advance.
  changelog?: ChangelogEntry[];
  items?: ChangelogEntry[];
}

/**
 * Fetches the full changelog for one dependency risk, most-recent-unknown-order
 * (the server's ordering isn't assumed — see findLastStatusChange).
 */
export async function fetchIssueReleaseChangelog(issueReleaseKey: string): Promise<ChangelogEntry[]> {
  const res = await fetch(`/api/v2/sca/issues-releases/${encodeURIComponent(issueReleaseKey)}/changelogs`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(
      `api/v2/sca/issues-releases/${issueReleaseKey}/changelogs failed: HTTP ${res.status}${text ? ' — ' + text : ''}`
    );
  }

  const raw = (await res.json()) as ChangelogPage;
  return raw.changelog ?? raw.items ?? [];
}

/**
 * Finds the most recent changelog entry that changed the risk's status
 * (changeData containing a fieldName === 'status' diff). Returns undefined if
 * the risk has never been manually transitioned — meaning no conflict is
 * possible against this risk.
 */
export function findLastStatusChange(changelog: ChangelogEntry[]): LastStatusChange | undefined {
  const statusEntries = changelog.filter((entry) =>
    (entry.changeData ?? []).some((change) => change.fieldName === 'status')
  );
  if (statusEntries.length === 0) {
    return undefined;
  }

  const latest = statusEntries.reduce((max, entry) =>
    Date.parse(entry.createdAt) >= Date.parse(max.createdAt) ? entry : max
  );

  return {
    createdAt: latest.createdAt,
    userLogin: latest.user?.login,
    userName: latest.user?.name,
    comment: latest.markdownComment,
  };
}
