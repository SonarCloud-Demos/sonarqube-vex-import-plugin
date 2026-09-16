import { syncPluginSettings } from './pluginSettings';

describe('syncPluginSettings', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('is enabled when the setting value is missing from the response', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({ settings: [] }) }) as unknown as typeof fetch;
    expect(await syncPluginSettings()).toEqual({ enabled: true });
  });

  it('is enabled when the setting value is anything other than the string "false"', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ settings: [{ key: 'veximport.enabled', value: 'true' }] }),
    }) as unknown as typeof fetch;
    expect(await syncPluginSettings()).toEqual({ enabled: true });
  });

  it('is disabled when the setting value is the string "false"', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ settings: [{ key: 'veximport.enabled', value: 'false' }] }),
    }) as unknown as typeof fetch;
    expect(await syncPluginSettings()).toEqual({ enabled: false });
  });

  it('fails open (enabled) when the request is not ok', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 403 }) as unknown as typeof fetch;
    expect(await syncPluginSettings()).toEqual({ enabled: true });
  });

  it('fails open (enabled) when fetch throws', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as unknown as typeof fetch;
    expect(await syncPluginSettings()).toEqual({ enabled: true });
  });
});
