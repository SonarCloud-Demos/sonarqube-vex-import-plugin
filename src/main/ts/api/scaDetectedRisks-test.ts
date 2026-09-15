import { fetchDetectedRisks } from './scaDetectedRisks';

describe('fetchDetectedRisks', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = jest.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('normalizes issue-release rows and extracts issueReleaseKey/transitions', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        issuesReleases: [
          {
            key: 'risk-1',
            status: 'OPEN',
            vulnerabilityId: 'CVE-2026-0001',
            transitions: ['ACCEPT', 'CONFIRM', 'SAFE'],
            release: { packageUrl: 'pkg:npm/express@4.19.2' },
          },
        ],
        page: { pageIndex: 1, pageSize: 1, total: 1 },
      }),
    } as Response);

    const items = await fetchDetectedRisks('my-project', 'main');

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v2/sca/issues-releases?projectKey=my-project&branchKey=main&pageIndex=1&pageSize=500',
      expect.objectContaining({ credentials: 'same-origin', headers: { Accept: 'application/json' } })
    );
    expect(items).toEqual([
      {
        issueReleaseKey: 'risk-1',
        projectKey: 'my-project',
        branchKey: 'main',
        vulnerabilityId: 'CVE-2026-0001',
        packageUrl: 'pkg:npm/express@4.19.2',
        status: 'OPEN',
        transitions: ['ACCEPT', 'CONFIRM', 'SAFE'],
      },
    ]);
  });

  it('falls back to the id field when key is absent, and to items[] envelope', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({
        items: [{ id: 'risk-2', status: 'CONFIRM', release: {} }],
        page: { pageIndex: 1, pageSize: 1, total: 1 },
      }),
    } as Response);

    const items = await fetchDetectedRisks('proj', 'main');
    expect(items).toEqual([
      { issueReleaseKey: 'risk-2', projectKey: 'proj', branchKey: 'main', vulnerabilityId: undefined, packageUrl: undefined, status: 'CONFIRM', transitions: [] },
    ]);
  });

  it('skips items with no key or id at all', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({ items: [{ status: 'OPEN' }], page: { pageIndex: 1, pageSize: 1, total: 1 } }),
    } as Response);

    const items = await fetchDetectedRisks('proj', 'main');
    expect(items).toEqual([]);
  });

  it('paginates until total is reached', async () => {
    (global.fetch as jest.Mock)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [{ key: 'a', status: 'OPEN' }],
          page: { pageIndex: 1, pageSize: 1, total: 2 },
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          items: [{ key: 'b', status: 'OPEN' }],
          page: { pageIndex: 2, pageSize: 1, total: 2 },
        }),
      } as Response);

    const items = await fetchDetectedRisks('proj', 'main');
    expect(items.map((i) => i.issueReleaseKey)).toEqual(['a', 'b']);
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('throws with the response body on a non-ok response', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'boom',
    } as Response);

    await expect(fetchDetectedRisks('proj', 'main')).rejects.toThrow('api/v2/sca/issues-releases failed: HTTP 500 — boom');
  });
});
