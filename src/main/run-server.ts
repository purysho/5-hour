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
import { recordEnrolment } from "../http/webhook-apply.ts";
import { createStripeClient } from "../billing/stripe.ts";
import { createBillingStore } from "../billing/provisioning.ts";

const config = loadConfig();

const db = new Database({
  connectionString: Secret.reveal(config.databaseUrl),
  platformConnectionString: Secret.reveal(config.platformDatabaseUrl),
});

// Narrowed once, here, so the closure below captures a `string` rather than
// re-asserting the union at every use.
const defaultProviderSlug = config.defaultProviderSlug;

let draining = false;

/**
 * Billing, composed once or not at all.
 *
 * `config.billing` is null for a deployment that does not sell, and the store
 * opens a connection pool with tenant-creation rights — so it is built only
 * when there is something to sell. The pool is closed on drain alongside the
 * main database.
 */
const billingStore =
  config.billing === null ? null : createBillingStore(config.billing.databaseUrl);

function log(message: string, fields: Record<string, unknown> = {}): void {
  // Structured, single line, no secrets. Secrets cannot reach here by
  // accident: Secret and ScopedToken both redact on serialisation.
  console.log(JSON.stringify({ level: "info", message, ...fields }));
}

const billingConfig = config.billing;

const server = createHttpServer({
  ready: () => !draining,
  log,

  ...(billingConfig === null || billingStore === null
    ? {}
    : {
        billing: {
          appInstallUrl: billingConfig.appInstallUrl,
          portalUrl: billingConfig.portalUrl,

          // Binding a payment to an installation. The only request in which
          // both facts exist — see src/http/setup.ts.
          setup: {
            log,
            providerForEnrolmentRef: async (refHash) => {
              const rows = await db.withPlatformContext("enrolment ref lookup", (client) =>
                client
                  .query<{ provider_id: string | null }>(
                    "SELECT provider_id_for_enrolment_ref($1) AS provider_id",
                    [refHash],
                  )
                  .then((r) => r.rows),
              );
              return rows[0]?.provider_id ?? null;
            },

            // Taken, not read: the row is deleted as it is returned, so two
            // concurrent setup callbacks for one installation cannot both
            // drain it.
            takePendingInstallation: async (forgeInstallationId) => {
              const rows = await db.withPlatformContext("drain parked installation", (client) =>
                client
                  .query<{ account: string; repositories: unknown }>(
                    `DELETE FROM pending_installation
                           WHERE forge_installation_id = $1
                       RETURNING account, repositories`,
                    [forgeInstallationId],
                  )
                  .then((r) => r.rows),
              );
              const row = rows[0];
              if (!row) return null;
              return {
                account: row.account,
                repositories: Array.isArray(row.repositories) ? row.repositories : [],
              };
            },

            enrol: async (providerId, forgeInstallationId, pending) => {
              await db.withTenant(providerId, (client) =>
                recordEnrolment(
                  client,
                  providerId,
                  // No parked delivery means the webhook has not arrived yet.
                  // The account is unknown at this moment, so the installation
                  // id stands in for it — the `installation.created` webhook
                  // that follows resolves to this tenant and corrects it.
                  pending?.account ?? `installation-${forgeInstallationId}`,
                  forgeInstallationId,
                  pending?.repositories ?? [],
                ),
              );
            },

            // Single-use. A reference is a bearer credential for binding an
            // installation to this tenant, and it has now been spent.
            consumeEnrolmentRef: async (providerId) => {
              await db.withTenant(providerId, (client) =>
                client.query("UPDATE provider SET enrolment_ref_hash = NULL WHERE id = $1", [
                  providerId,
                ]),
              );
            },
          },
          checkout: {
            stripe: createStripeClient(billingConfig.secretKey),
            priceIds: billingConfig.priceIds,
            publicOrigin: config.http.publicOrigin,
            log,
          },
          webhook: {
            secret: billingConfig.webhookSecret,
            store: billingStore,
            priceIds: billingConfig.priceIds,
            log,
          },
        },
      }),

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
    // Self-serve deployments park an installation whose tenant is not yet
    // known; the setup callback claims it. Absent when billing is off, where
    // DEFAULT_PROVIDER_SLUG answers the question instead.
    ...(billingConfig === null
      ? {}
      : {
          parkInstallation: async (forgeInstallationId, account, repositories) => {
            await db.withPlatformContext("park installation", (client) =>
              client.query(
                `INSERT INTO pending_installation
                       (forge_installation_id, account, repositories)
                     VALUES ($1, $2, $3::jsonb)
                ON CONFLICT (forge_installation_id) DO UPDATE
                   SET account = EXCLUDED.account,
                       repositories = EXCLUDED.repositories,
                       received_at = now()`,
                [forgeInstallationId, account, JSON.stringify(repositories)],
              ),
            );
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
    void Promise.all([db.close(), billingStore?.close() ?? Promise.resolve()]).then(() =>
      process.exit(0),
    );
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
