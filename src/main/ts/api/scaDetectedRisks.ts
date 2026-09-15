export interface DetectedRisk {
  issueReleaseKey: string;
  projectKey: string;
  branchKey: string;
  vulnerabilityId?: string;
  packageUrl?: string;
  status: string;
  transitions: string[];
}

interface IssueReleaseResource {
  key?: string;
  id?: string;
  status?: string;
  vulnerabilityId?: string;
  transitions?: string[];
  release?: { packageUrl?: string };
}

interface IssuesReleasesPage {
  // SonarQube v2 paginated response — array key varies by server version
  issueReleases?: IssueReleaseResource[];
  issuesReleases?: IssueReleaseResource[];
  items?: IssueReleaseResource[];
  page?: { pageIndex: number; pageSize: number; total: number };
  paging?: { pageIndex: number; pageSize: number; total: number };
}

function extractPage(raw: IssuesReleasesPage): {
  items: IssueReleaseResource[];
  pageIndex: number;
  pageSize: number;
  total: number;
} {
  const items = raw.issueReleases ?? raw.issuesReleases ?? raw.items ?? [];
  const p = raw.page ?? raw.paging;
  return {
    items,
    pageIndex: p?.pageIndex ?? 1,
    pageSize: p?.pageSize ?? items.length,
    total: p?.total ?? items.length,
  };
}

function normalize(item: IssueReleaseResource, projectKey: string, branchKey: string): DetectedRisk | undefined {
  const issueReleaseKey = item.key ?? item.id;
  if (!issueReleaseKey) {
    return undefined;
  }
  return {
    issueReleaseKey,
    projectKey,
    branchKey,
    vulnerabilityId: item.vulnerabilityId,
    packageUrl: item.release?.packageUrl,
    status: item.status ?? 'OPEN',
    transitions: item.transitions ?? [],
  };
}

/**
 * Fetches the dependency risks SonarQube has currently detected for a
 * (project, branch) pair, from /api/v2/sca/issues-releases. Each result
 * carries the issueReleaseKey and transitions[] needed to match against
 * and apply a VEX-driven status change.
 */
export async function fetchDetectedRisks(projectKey: string, branchKey: string): Promise<DetectedRisk[]> {
  const allItems: DetectedRisk[] = [];
  let pageIndex = 1;
  const pageSize = 500;

  while (true) {
    const qs = new URLSearchParams({
      projectKey,
      branchKey,
      pageIndex: String(pageIndex),
      pageSize: String(pageSize),
    });

    const res = await fetch(`/api/v2/sca/issues-releases?${qs}`, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(
        `api/v2/sca/issues-releases failed: HTTP ${res.status}${text ? ' — ' + text : ''}`
      );
    }

    const raw = (await res.json()) as IssuesReleasesPage;
    const page = extractPage(raw);

    for (const item of page.items) {
      const normalized = normalize(item, projectKey, branchKey);
      if (normalized) {
        allItems.push(normalized);
      }
    }

    if (page.items.length === 0 || pageIndex * page.pageSize >= page.total) break;
    pageIndex++;
  }

  return allItems;
}
