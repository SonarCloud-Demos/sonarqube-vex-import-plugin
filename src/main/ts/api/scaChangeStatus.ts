import { getCsrfToken } from '../utils/csrf';
import { concurrentMap } from '../utils/concurrentMap';

export interface StatusChangeRequest {
  issueReleaseKey: string;
  transitionKey: string;
  comment: string;
}

export interface StatusChangeResult {
  issueReleaseKey: string;
  ok: boolean;
  error?: string;
}

function postJson(url: string, body: unknown): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-XSRF-TOKEN': getCsrfToken(),
    },
    body: JSON.stringify(body),
  });
}

async function applySingle(change: StatusChangeRequest): Promise<StatusChangeResult> {
  try {
    const res = await postJson('/api/v2/sca/issues-releases/change-status', change);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { issueReleaseKey: change.issueReleaseKey, ok: false, error: `HTTP ${res.status}${text ? ' — ' + text : ''}` };
    }
    return { issueReleaseKey: change.issueReleaseKey, ok: true };
  } catch (e) {
    return { issueReleaseKey: change.issueReleaseKey, ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

async function applySequentially(changes: StatusChangeRequest[]): Promise<StatusChangeResult[]> {
  return concurrentMap(changes, 5, applySingle);
}

/**
 * Applies a batch of dependency-risk status changes. Tries the bulk-change
 * endpoint first (one request); if that call itself fails before any
 * per-item result is known — e.g. because its exact contract differs from
 * what's expected here — falls back to sequential single-item calls so the
 * import still completes correctly.
 */
export async function applyStatusChanges(changes: StatusChangeRequest[]): Promise<StatusChangeResult[]> {
  if (changes.length === 0) {
    return [];
  }
  if (changes.length === 1) {
    return [await applySingle(changes[0])];
  }

  // The bulk endpoint applies one transitionKey/comment to a set of keys — it
  // isn't a fit when items in the batch need different transitions/comments,
  // which is the common case for a VEX import (each risk can map to a
  // different status). Only ever attempt it when every item in this batch
  // shares the same transitionKey and comment, so a speculative bulk call
  // can never apply the wrong transition to an item that needed a different
  // one. Any other case — including a bulk-call failure — falls back to
  // per-item calls, which always apply correctly regardless of the bulk
  // endpoint's exact contract.
  const homogeneous = changes.every(
    (c) => c.transitionKey === changes[0].transitionKey && c.comment === changes[0].comment
  );

  if (homogeneous) {
    try {
      const res = await postJson('/api/v2/sca/issues-releases/bulk-change', {
        issueReleaseKeys: changes.map((c) => c.issueReleaseKey),
        transitionKey: changes[0].transitionKey,
        comment: changes[0].comment,
      });
      if (res.ok) {
        return changes.map((c) => ({ issueReleaseKey: c.issueReleaseKey, ok: true }));
      }
    } catch {
      // fall through to sequential
    }
  }

  return applySequentially(changes);
}
