const ENABLED_SETTING_KEY = 'veximport.enabled';

/**
 * Checks whether an administrator has disabled the plugin (Administration →
 * General Settings → VEX Import). Call once per page load, before doing
 * anything else - if `enabled` comes back false, the caller should render a
 * disabled notice and skip every other fetch.
 *
 * Note: when the setting is off, the page/menu entry itself is normally
 * already gone (VexImportPageDefinition doesn't register it - see its
 * Javadoc) - but that requires a SonarQube restart to take effect. This
 * check is what makes disabling effective *immediately*, in the gap before
 * that restart, and is defense-in-depth afterward. Fails open (enabled) if
 * the settings call itself fails, since a broken settings fetch shouldn't
 * be indistinguishable from an administrator disabling the feature.
 */
export async function syncPluginSettings(): Promise<{ enabled: boolean }> {
  let enabled = true;
  try {
    const res = await fetch(`/api/settings/values?keys=${ENABLED_SETTING_KEY}`, {
      credentials: 'same-origin',
    });
    if (res.ok) {
      const data = (await res.json()) as { settings?: Array<{ key: string; value?: string }> };
      const enabledValue = (data.settings ?? []).find((s) => s.key === ENABLED_SETTING_KEY)?.value;
      if (enabledValue !== undefined) enabled = enabledValue !== 'false';
    }
  } catch {
    // keep default (enabled)
  }
  return { enabled };
}
