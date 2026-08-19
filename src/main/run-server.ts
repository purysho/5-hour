/**
 * Server entry point.
 *
 * Wires configuration to the HTTP surface and nothing else. Everything it
 * needs already exists and is tested; this file is composition, so it stays
 * thin enough to read in one pass.
 */

import { loadConfig, Secret } from "../config.ts";
import { Database } from "../db/client.ts";
import { createHttpServer } from "./server.ts";
import { hashToken } from "../outbound/suppression.ts";

const config = loadConfig();

const db = new Database({
  connectionString: Secret.reveal(config.databaseUrl),
  platformConnectionString: Secret.reveal(config.platformDatabaseUrl),
});

// Narrowed once, here, so the closure below captures a `string` rather than
// re-asserting the union at every use.
const defaultProviderSlug = config.defaultProviderSlug;

let draining = false;

function log(message: string, fields: Record<string, unknown> = {}): void {
  // Structured, single line, no secrets. Secrets cannot reach here by
  // accident: Secret and ScopedToken both redact on serialisation.
  console.log(JSON.stringify({ level: "info", message, ...fields }));
}

const server = createHttpServer({
  ready: () => !draining,
  log,

  optOut: {
    withTenant: (providerId, fn) => db.withTenant(providerId, fn),
    hashToken,
    // Minimal-disclosure tenant resolution (migration 005). Returns a provider
    // id and nothing else.
    providerForToken: async (tokenHash) => {
      const rows = await db.withPlatformContext("opt-out token lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_for_opt_out_token($1) AS provider_id",
            [tokenHash],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
  },

  webhook: {
    secret: Secret.reveal(config.github.webhookSecret),
    claimDelivery: async (deliveryId) => {
      const rows = await db.withPlatformContext("webhook delivery claim", (client) =>
        client
          .query<{ claim_webhook_delivery: boolean }>(
            "SELECT claim_webhook_delivery($1, NULL)",
            [deliveryId],
          )
          .then((r) => r.rows),
      );
      // The function returns true when THIS caller claimed it; the webhook
      // handler wants "already seen", so the sense is inverted here rather
      // than in either of the two places that would make it ambiguous.
      return rows[0]?.claim_webhook_delivery === false;
    },
  },

  apply: {
    withTenant: (providerId, fn) => db.withTenant(providerId, fn),
    // Present only when a provider is configured, so that "no enrolment" stays
    // a shape the type system can see rather than a null checked at runtime.
    ...(defaultProviderSlug === null
      ? {}
      : {
          defaultProvider: async () => {
            const rows = await db.withPlatformContext("enrolment provider lookup", (client) =>
              client
                .query<{ provider_id: string | null }>(
                  "SELECT provider_id_for_slug($1) AS provider_id",
                  [defaultProviderSlug],
                )
                .then((r) => r.rows),
            );
            return rows[0]?.provider_id ?? null;
          },
        }),
    providerForInstallation: async (forgeInstallationId) => {
      const rows = await db.withPlatformContext("installation lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_for_installation($1) AS provider_id",
            [forgeInstallationId],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
  },
});

server.listen(config.http.port, () => {
  log("server listening", { port: config.http.port, env: config.env });
});

/**
 * Drain before closing.
 *
 * /health starts failing immediately so the load balancer stops routing to
 * us, then in-flight requests finish. Closing the listener first would reject
 * requests that were already accepted.
 */
function shutdown(signal: string): void {
  if (draining) {
    log("second signal — exiting immediately", { signal });
    process.exit(130);
  }
  draining = true;
  log("draining", { signal });

  server.close(() => {
    void db.close().then(() => process.exit(0));
  });

  // Backstop. A hung keep-alive connection must not hold the process open past
  // the orchestrator's own kill timeout.
  setTimeout(() => {
    log("drain timeout — exiting", { signal });
    process.exit(1);
  }, config.worker.shutdownGraceMs).unref();
}

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => shutdown(signal));
}
