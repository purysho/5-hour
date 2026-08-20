/**
 * Pre-flight: does this deployment actually hold what it thinks it holds?
 *
 * Every check here answers a question that is otherwise only answered in
 * production, usually at the worst moment. The two that matter most:
 *
 *   **Does the private key belong to this App?** An App ID and a `.pem` that
 *   came from different Apps produce a JWT GitHub rejects, and the first place
 *   you find out is the first token mint — inside a job, behind a retry.
 *
 *   **Is the permission manifest still what ADR-0002 §4 says?** A widened
 *   manifest is a settings change on a web page, made in ten seconds, with no
 *   diff and no review. `write` on `administration` or `workflows` would
 *   destroy the guarantee that human review cannot be bypassed. This is the
 *   only automated check that a box has not been ticked.
 *
 * Read-only throughout. It mints nothing, writes nothing, and opens nothing.
 * Safe to run against production whenever something feels wrong.
 *
 * Nothing secret is printed — not the key, not the JWT, not a connection
 * string. The output is intended to be pasteable into an issue.
 *
 *   pnpm preflight
 */

import pg from "pg";
import { loadConfig, Secret, ConfigError, type Config } from "../src/config.ts";
import { createAppJwt, FileSigner, KmsSigner, type Signer } from "../src/github/signer.ts";
import { AwsKmsClient } from "../src/github/kms-signer.ts";
import { FORBIDDEN_PERMISSIONS, REQUIRED_PERMISSIONS } from "../src/github/token.ts";

type Level = "pass" | "warn" | "fail";

interface Result {
  readonly level: Level;
  readonly check: string;
  readonly detail: string;
}

const results: Result[] = [];

function record(level: Level, check: string, detail: string): void {
  results.push({ level, check, detail });
}

// ── 1. Configuration ────────────────────────────────────────────────────────

let config: Config | null = null;
try {
  config = loadConfig();
  record("pass", "configuration", `loaded, NODE_ENV=${config.env}`);
} catch (error) {
  // loadConfig reports every problem at once, so this is the whole list.
  record(
    "fail",
    "configuration",
    error instanceof ConfigError ? error.message : String(error),
  );
}

// ── 2. Signing key ──────────────────────────────────────────────────────────

let signer: Signer | null = null;
if (config) {
  try {
    if (config.github.signing.kind === "kms") {
      // A real client. This was a stub that threw, on the reasoning that
      // preflight should not assume it has AWS credentials — but preflight is
      // run on the host that is about to serve traffic, where those
      // credentials exist by definition, and the stub made every check below
      // it silently skip.
      //
      // That is how a KMS key whose material GitHub had never issued reached
      // production: preflight reported five checks, none failing, and never
      // once asked GitHub whether the key worked. A signature costs a
      // fraction of a cent and is the only thing that answers the question.
      signer = new KmsSigner(new AwsKmsClient(), config.github.signing.keyId);
      record("pass", "signing key", `KMS ${config.github.signing.keyId} — exercised below`);
    } else {
      signer = new FileSigner(config.github.signing.path);
      record(
        process.platform === "win32" ? "warn" : "pass",
        "signing key",
        process.platform === "win32"
          ? `file (${config.github.signing.path}) — permissions NOT verified; Windows ` +
            "has no POSIX mode and the ACL was asserted by hand (ADR-0012)"
          : `file, mode 600 or tighter (${config.github.signing.path}) — interim, see ADR-0012`,
      );
    }
  } catch (error) {
    record("fail", "signing key", (error as Error).message);
  }
}

// ── 3. The App is who we think it is ────────────────────────────────────────

interface AppResponse {
  id?: number;
  slug?: string;
  name?: string;
  owner?: { login?: string };
  permissions?: Record<string, string>;
  events?: string[];
  html_url?: string;
}

let app: AppResponse | null = null;

if (config && signer) {
  try {
    const jwt = await createAppJwt(signer, config.github.appId);
    const response = await fetch("https://api.github.com/app", {
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "user-agent": "driftless-preflight",
      },
    });

    if (response.status === 401) {
      record(
        "fail",
        "app identity",
        "GitHub rejected the App JWT. The private key does not belong to " +
          `App ${config.github.appId}, or the key has been revoked.`,
      );
    } else if (!response.ok) {
      record("fail", "app identity", `GET /app returned ${response.status}`);
    } else {
      app = (await response.json()) as AppResponse;
      if (String(app.id) !== config.github.appId) {
        record(
          "fail",
          "app identity",
          `GITHUB_APP_ID is ${config.github.appId} but this key belongs to App ${app.id}`,
        );
      } else {
        record(
          "pass",
          "app identity",
          `${app.slug} (id ${app.id}), owned by ${app.owner?.login ?? "unknown"}`,
        );
      }
    }
  } catch (error) {
    // Signing and reaching GitHub fail differently and deserve different
    // verdicts. A key that cannot produce a signature is a broken deployment;
    // a network that cannot be reached from here is a limitation of where
    // preflight is being run.
    const message = (error as Error).message;
    const signingFailed = /KMS|sign|key/i.test(message);
    record(
      signingFailed ? "fail" : "warn",
      "app identity",
      signingFailed
        ? `could not sign an App JWT: ${message}`
        : `could not reach GitHub: ${message}`,
    );
  }
}

// ── 4. The permission manifest ──────────────────────────────────────────────
//
// The check this script exists for. Widening the manifest is a settings change
// on a web page — no diff, no review, ten seconds — and `administration` or
// `workflows` would end the guarantee that human review cannot be bypassed.

if (!app?.permissions) {
  // The check this script exists for, and it was reachable only when the App
  // identity had been established — so when identity could not be established
  // it recorded nothing at all, and `preflight` exited 0 having verified the
  // one thing it is named for exactly not at all. A check that silently does
  // not run is worse than one that is absent: absence is visible.
  record(
    "fail",
    "permissions: required",
    "not checked — the App's permission manifest could not be read. " +
      "Every check above that needed an App JWT will say why.",
  );
} else {
  const granted = app.permissions;

  const missing = Object.entries(REQUIRED_PERMISSIONS).filter(
    ([name, level]) => granted[name] !== level,
  );
  if (missing.length > 0) {
    record(
      "fail",
      "permissions: required",
      `missing or too weak: ${missing.map(([n, l]) => `${n}=${l}`).join(", ")}`,
    );
  } else {
    record("pass", "permissions: required", "contents=write, pull_requests=write");
  }

  const forbidden = FORBIDDEN_PERMISSIONS.filter((name) => granted[name] !== undefined);
  if (forbidden.length > 0) {
    record(
      "fail",
      "permissions: forbidden",
      `App holds ${forbidden.join(", ")} — remove it. ADR-0002 §4 and threat-model §2.`,
    );
  } else {
    record("pass", "permissions: forbidden", "none of the forbidden permissions are held");
  }

  const extra = Object.keys(granted).filter((name) => !(name in REQUIRED_PERMISSIONS));
  if (extra.length > 0) {
    // Not a failure — some are harmless read scopes — but every one of them is
    // capability nothing in the codebase uses, and unused capability is what a
    // compromise spends.
    record(
      "warn",
      "permissions: extra",
      `App also holds ${extra.map((n) => `${n}=${granted[n]}`).join(", ")}; ` +
        "nothing in Driftless uses these",
    );
  }
}

if (app?.events) {
  const unexpected = app.events.filter((event) => event !== "pull_request");
  record(
    unexpected.length > 0 ? "warn" : "pass",
    "webhook events",
    unexpected.length > 0
      ? `subscribed to ${app.events.join(", ")}; only pull_request is used`
      : app.events.length > 0
        ? "pull_request only"
        : "none subscribed yet",
  );
}

// ── 5. Installations ────────────────────────────────────────────────────────

if (config && signer && app) {
  try {
    const jwt = await createAppJwt(signer, config.github.appId);
    const response = await fetch("https://api.github.com/app/installations?per_page=100", {
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "user-agent": "driftless-preflight",
      },
    });

    if (!response.ok) {
      record("warn", "installations", `GET /app/installations returned ${response.status}`);
    } else {
      const installations = (await response.json()) as {
        id: number;
        account?: { login?: string };
        repository_selection?: string;
      }[];

      if (installations.length === 0) {
        record("warn", "installations", "none yet — install the App on a test repository");
      } else {
        for (const installation of installations) {
          const all = installation.repository_selection === "all";
          record(
            all ? "warn" : "pass",
            "installations",
            `${installation.account?.login ?? "unknown"} (id ${installation.id}), ` +
              `repositories: ${installation.repository_selection}` +
              (all ? " — prefer selected repositories while acting on your own" : ""),
          );
        }
      }
    }
  } catch (error) {
    record("warn", "installations", `could not reach GitHub: ${(error as Error).message}`);
  }
}

// ── 6. Database roles ───────────────────────────────────────────────────────
//
// ADR-0010: no login role may hold both `driftless_app` and `driftless_admin`.
// Postgres ORs together the policies of every role you belong to, so combining
// them grants cross-tenant visibility with no error and nothing to see in
// review — which makes it exactly the kind of thing a check has to catch.

/** The schema is a property of the database, not of whoever connected to it. */
let checkedMigrations = false;

if (config) {
  await checkRole("app role", Secret.reveal(config.databaseUrl));
  const platform = Secret.reveal(config.platformDatabaseUrl);
  if (platform !== Secret.reveal(config.databaseUrl)) {
    await checkRole("platform role", platform);
  } else {
    record(
      "warn",
      "platform role",
      "PLATFORM_DATABASE_URL is unset, so both roles are the same login — " +
        "acceptable in development, never in production (ADR-0010)",
    );
  }
}

async function checkRole(label: string, connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString, connectionTimeoutMillis: 5_000 });
  try {
    await client.connect();

    const { rows } = await client.query<{
      current_user: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
    }>(
      `SELECT current_user, r.rolsuper, r.rolbypassrls
       FROM pg_roles r WHERE r.rolname = current_user`,
    );
    const role = rows[0];
    if (!role) {
      record("fail", label, "connected, but could not read the current role");
      return;
    }

    if (role.rolsuper || role.rolbypassrls) {
      record(
        "fail",
        label,
        `${role.current_user} is superuser or has BYPASSRLS — row-level security ` +
          "does not apply to it, which makes every isolation guarantee vacuous",
      );
      return;
    }

    const { rows: memberships } = await client.query<{ rolname: string }>(
      `SELECT g.rolname FROM pg_auth_members m
       JOIN pg_roles g ON g.oid = m.roleid
       JOIN pg_roles u ON u.oid = m.member
       WHERE u.rolname = current_user`,
    );
    const held = memberships.map((m) => m.rolname);
    const both = held.includes("driftless_app") && held.includes("driftless_admin");

    record(
      both ? "fail" : "pass",
      label,
      both
        ? `${role.current_user} holds both driftless_app and driftless_admin — ` +
          "Postgres ORs their policies together, silently granting cross-tenant " +
          "visibility (ADR-0010)"
        : `${role.current_user}, member of ${held.join(", ") || "no group role"}`,
    );

    if (checkedMigrations) return;
    checkedMigrations = true;

    // `pg_class` rather than `information_schema.tables`, which is filtered by
    // privilege — the platform role holds grants on two of these, so the
    // information_schema view would report a missing migration for a database
    // that is entirely up to date.
    const expected = [
      "provider",
      "outbound_write",
      "job",
      "suppression",
      "webhook_delivery",
      "watched_package",
    ];
    const { rows: present } = await client.query<{ relname: string }>(
      `SELECT c.relname FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE c.relkind = 'r' AND n.nspname = 'public' AND c.relname = ANY($1)`,
      [expected],
    );
    const missingTables = expected.filter(
      (name) => !present.some((row) => row.relname === name),
    );
    record(
      missingTables.length === 0 ? "pass" : "fail",
      "migrations",
      missingTables.length === 0
        ? "001–007 applied"
        : `missing ${missingTables.join(", ")} — run pnpm db:migrate`,
    );
  } catch (error) {
    record("fail", label, `could not connect: ${(error as Error).message}`);
  } finally {
    await client.end().catch(() => {});
  }
}

// ── 7. Migration generation ─────────────────────────────────────────────────

if (config) {
  record(
    config.anthropic.apiKey ? "pass" : "warn",
    "model access",
    config.anthropic.apiKey
      ? "ANTHROPIC_API_KEY is set (not exercised here — a live call costs tokens)"
      : "ANTHROPIC_API_KEY is unset; the worker will run detect-changes only",
  );
}

// ── Report ──────────────────────────────────────────────────────────────────

const icon = (level: Level): string =>
  level === "pass" ? "  ok  " : level === "warn" ? " warn " : " FAIL ";

console.log("\nDriftless pre-flight\n");
for (const result of results) {
  console.log(`[${icon(result.level)}] ${result.check.padEnd(24)} ${result.detail}`);
}

const failures = results.filter((r) => r.level === "fail").length;
const warnings = results.filter((r) => r.level === "warn").length;
console.log(
  `\n${results.length} checks, ${failures} failing, ${warnings} warning\n`,
);

if (failures > 0) {
  console.log("Fix the failures before deploying. docs/DEPLOYMENT.md has the detail.\n");
  process.exit(1);
}
