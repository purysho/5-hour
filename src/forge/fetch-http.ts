/**
 * The one `ForgeHttpClient` backed by a real network.
 *
 * Extracted so the worker and the operator scripts share it rather than each
 * carrying their own eight lines. The shape matters more than the size: every
 * GitHub call in this system goes through an injected client, so that code
 * handling a credential does not inherit an SDK's error messages — which are a
 * common route for a token to reach a log — and so tests exercise the real
 * request sequence without a network.
 *
 * Nothing here logs. A request carries an Authorization header, and a client
 * that logged its own requests would be the one place a credential reliably
 * leaks.
 */

import type { ForgeHttpClient } from "./github-forge.ts";

export function createFetchHttpClient(fetchImpl: typeof fetch = fetch): ForgeHttpClient {
  return {
    async request(method, url, body, headers) {
      const response = await fetchImpl(url, {
        method,
        headers: { ...headers, ...(body !== undefined && { "content-type": "application/json" }) },
        ...(body !== undefined && { body: JSON.stringify(body) }),
      });
      return { status: response.status, body: await response.text() };
    },
  };
}
