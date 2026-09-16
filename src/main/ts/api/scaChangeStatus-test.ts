import { applyStatusChanges } from './scaChangeStatus';

describe('applyStatusChanges', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = jest.fn() as unknown as typeof fetch;
    document.cookie = 'XSRF-TOKEN=test-token';
  });

  afterEach(() => {
    global.fetch = originalFetch;
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });

  it('returns an empty array for an empty batch without calling fetch', async () => {
    const results = await applyStatusChanges([]);
    expect(results).toEqual([]);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('calls change-status directly for a single item, with the CSRF header', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: true });

    const results = await applyStatusChanges([{ issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'c1' }]);

    expect(results).toEqual([{ issueReleaseKey: 'k1', ok: true }]);
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v2/sca/issues-releases/change-status',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-XSRF-TOKEN': 'test-token' }),
        body: JSON.stringify({ issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'c1' }),
      })
    );
  });

  it('uses the bulk endpoint when every item in the batch shares transitionKey and comment', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: true });
    const changes = [
      { issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'same' },
      { issueReleaseKey: 'k2', transitionKey: 'SAFE', comment: 'same' },
    ];

    const results = await applyStatusChanges(changes);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v2/sca/issues-releases/bulk-change',
      expect.objectContaining({
        body: JSON.stringify({ issueReleaseKeys: ['k1', 'k2'], transitionKey: 'SAFE', comment: 'same' }),
      })
    );
    expect(results).toEqual([
      { issueReleaseKey: 'k1', ok: true },
      { issueReleaseKey: 'k2', ok: true },
    ]);
  });

  it('never calls bulk-change for a heterogeneous batch — goes straight to per-item calls', async () => {
    (global.fetch as jest.Mock).mockResolvedValue({ ok: true });
    const changes = [
      { issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'a' },
      { issueReleaseKey: 'k2', transitionKey: 'FIXED', comment: 'b' },
    ];

    const results = await applyStatusChanges(changes);

    const urlsCalled = (global.fetch as jest.Mock).mock.calls.map((c) => c[0]);
    expect(urlsCalled).not.toContain('/api/v2/sca/issues-releases/bulk-change');
    expect(urlsCalled.every((u) => u === '/api/v2/sca/issues-releases/change-status')).toBe(true);
    expect([...results].sort((a, b) => a.issueReleaseKey.localeCompare(b.issueReleaseKey))).toEqual([
      { issueReleaseKey: 'k1', ok: true },
      { issueReleaseKey: 'k2', ok: true },
    ]);
  });

  it('falls back to sequential calls when the bulk call fails', async () => {
    (global.fetch as jest.Mock)
      .mockResolvedValueOnce({ ok: false, status: 404, text: async () => 'not found' }) // bulk-change
      .mockResolvedValue({ ok: true }); // each change-status fallback call

    const changes = [
      { issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'same' },
      { issueReleaseKey: 'k2', transitionKey: 'SAFE', comment: 'same' },
    ];

    const results = await applyStatusChanges(changes);

    expect(global.fetch).toHaveBeenCalledTimes(3); // 1 bulk attempt + 2 fallback calls
    expect([...results].sort((a, b) => a.issueReleaseKey.localeCompare(b.issueReleaseKey))).toEqual([
      { issueReleaseKey: 'k1', ok: true },
      { issueReleaseKey: 'k2', ok: true },
    ]);
  });

  it('reports a per-item failure without failing the whole batch', async () => {
    const changes = [
      { issueReleaseKey: 'k1', transitionKey: 'SAFE', comment: 'a' },
      { issueReleaseKey: 'k2', transitionKey: 'FIXED', comment: 'b' },
    ];
    (global.fetch as jest.Mock).mockImplementation((_url: string, opts: { body: string }) => {
      const body = JSON.parse(opts.body);
      if (body.issueReleaseKey === 'k2') {
        return Promise.resolve({ ok: false, status: 400, text: async () => 'comment required' });
      }
      return Promise.resolve({ ok: true });
    });

    const results = await applyStatusChanges(changes);
    expect([...results].sort((a, b) => a.issueReleaseKey.localeCompare(b.issueReleaseKey))).toEqual([
      { issueReleaseKey: 'k1', ok: true },
      { issueReleaseKey: 'k2', ok: false, error: 'HTTP 400 — comment required' },
    ]);
  });
});
