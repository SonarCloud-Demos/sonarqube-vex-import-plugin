import { fetchIssueReleaseChangelog, findLastStatusChange, ChangelogEntry } from './scaChangelog';

function entry(overrides: Partial<ChangelogEntry> = {}): ChangelogEntry {
  return {
    key: 'c1',
    createdAt: '2026-01-01T00:00:00Z',
    changeData: [{ fieldName: 'status', oldValue: 'OPEN', newValue: 'SAFE' }],
    ...overrides,
  };
}

describe('fetchIssueReleaseChangelog', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = jest.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('fetches the changelog for the given key', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({ changelog: [{ key: 'c1', createdAt: '2026-01-01T00:00:00Z' }] }),
    } as Response);

    const result = await fetchIssueReleaseChangelog('risk-1');

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v2/sca/issues-releases/risk-1/changelogs',
      expect.objectContaining({ credentials: 'same-origin', headers: { Accept: 'application/json' } })
    );
    expect(result).toEqual([{ key: 'c1', createdAt: '2026-01-01T00:00:00Z' }]);
  });

  it('URL-encodes the issueReleaseKey', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: true, json: async () => ({ changelog: [] }) } as Response);
    await fetchIssueReleaseChangelog('risk/with space');
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v2/sca/issues-releases/risk%2Fwith%20space/changelogs',
      expect.anything()
    );
  });

  it('returns an empty array when the changelog key is absent', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: true, json: async () => ({}) } as Response);
    expect(await fetchIssueReleaseChangelog('risk-1')).toEqual([]);
  });

  it('falls back to an items[] envelope', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      json: async () => ({ items: [{ key: 'c2', createdAt: '2026-01-02T00:00:00Z' }] }),
    } as Response);
    expect(await fetchIssueReleaseChangelog('risk-1')).toEqual([{ key: 'c2', createdAt: '2026-01-02T00:00:00Z' }]);
  });

  it('throws with the response body on a non-ok response', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: false, status: 404, text: async () => 'not found' } as Response);
    await expect(fetchIssueReleaseChangelog('risk-1')).rejects.toThrow(
      'api/v2/sca/issues-releases/risk-1/changelogs failed: HTTP 404 — not found'
    );
  });
});

describe('findLastStatusChange', () => {
  it('returns undefined for an empty changelog', () => {
    expect(findLastStatusChange([])).toBeUndefined();
  });

  it('returns undefined when no entry changed the status field', () => {
    const changelog = [entry({ changeData: [{ fieldName: 'severity', oldValue: 'LOW', newValue: 'HIGH' }] })];
    expect(findLastStatusChange(changelog)).toBeUndefined();
  });

  it('returns the single status-change entry, flattened', () => {
    const result = findLastStatusChange([
      entry({ user: { login: 'jdoe', name: 'Jane Doe' }, markdownComment: 'looks safe' }),
    ]);
    expect(result).toEqual({
      createdAt: '2026-01-01T00:00:00Z',
      userLogin: 'jdoe',
      userName: 'Jane Doe',
      comment: 'looks safe',
    });
  });

  it('picks the most recent status-change entry even when the array is not sorted', () => {
    const changelog = [
      entry({ key: 'newer', createdAt: '2026-03-01T00:00:00Z' }),
      entry({ key: 'older', createdAt: '2026-01-01T00:00:00Z' }),
      entry({ key: 'middle', createdAt: '2026-02-01T00:00:00Z' }),
    ];
    expect(findLastStatusChange(changelog)?.createdAt).toBe('2026-03-01T00:00:00Z');
  });

  it('ignores non-status entries mixed into an otherwise status-bearing changelog', () => {
    const changelog = [
      entry({ key: 'status-1', createdAt: '2026-01-01T00:00:00Z' }),
      entry({ key: 'comment-only', createdAt: '2026-05-01T00:00:00Z', changeData: [] }),
    ];
    expect(findLastStatusChange(changelog)?.createdAt).toBe('2026-01-01T00:00:00Z');
  });
});
