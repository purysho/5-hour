import { describe, expect, it } from "vitest";
import {
  handleWebhook,
  signBody,
  type RawWebhook,
  type WebhookDeps,
  type WebhookOutcome,
} from "../../src/http/webhook.ts";

/**
 * Webhook ingestion.
 *
 * A public, unauthenticated endpoint where the only thing separating a real
 * delivery from a forgery is an HMAC. It also carries the customer's
 * revocation path: when someone uninstalls the app, GitHub tells us here and
 * nowhere else.
 *
 * So the tests are mostly forgery attempts, plus proof that revocation lands.
 */

const SECRET = "webhook-secret-value";

function deliver(
  body: unknown,
  overrides: {
    event?: string;
    secret?: string;
    signature?: string | null;
    deliveryId?: string | null;
    rawBody?: string;
  } = {},
): RawWebhook {
  const raw = overrides.rawBody ?? JSON.stringify(body);
  const headers: Record<string, string | undefined> = {
    "x-github-event": overrides.event ?? "installation",
  };
  if (overrides.signature !== null) {
    headers["x-hub-signature-256"] =
      overrides.signature ?? signBody(raw, overrides.secret ?? SECRET);
  }
  if (overrides.deliveryId !== null) {
    headers["x-github-delivery"] =
      overrides.deliveryId ?? "12345678-1234-1234-1234-123456789abc";
  }
  return { body: raw, headers };
}

function deps(seen: Set<string> = new Set()): WebhookDeps {
  return {
    secret: SECRET,
    async claimDelivery(id) {
      if (seen.has(id)) return true;
      seen.add(id);
      return false;
    },
  };
}

const INSTALLATION = { id: 12345 };

function rejection(outcome: WebhookOutcome): string {
  return outcome.kind === "rejected" ? outcome.reason : `not-rejected(${outcome.kind})`;
}

describe("forgery", () => {
  it("rejects a wrong signature", async () => {
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }, { secret: "wrong-secret" }),
      deps(),
    );
    expect(rejection(outcome)).toBe("bad-signature");
  });

  it("rejects a missing signature rather than treating it as optional", async () => {
    // The tempting shape is "if a signature is present, check it" — which an
    // attacker satisfies by omitting the header.
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }, { signature: null }),
      deps(),
    );
    expect(rejection(outcome)).toBe("missing-signature");
  });

  it("rejects an empty signature header", async () => {
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }, { signature: "" }),
      deps(),
    );
    expect(rejection(outcome)).toBe("missing-signature");
  });

  it("rejects a signature of the wrong length without throwing", async () => {
    // timingSafeEqual throws on length mismatch. An unhandled throw here is
    // both a crash and a timing signal.
    for (const signature of ["sha256=", "sha256=aa", "x", "sha256=" + "a".repeat(200)]) {
      const outcome = await handleWebhook(
        deliver({ action: "deleted", installation: INSTALLATION }, { signature }),
        deps(),
      );
      expect(rejection(outcome), signature).toBe("bad-signature");
    }
  });

  it("verifies the raw body, not a re-serialised parse of it", async () => {
    // JSON round-tripping is not byte-preserving, so verifying after parsing
    // lets a body authenticate as one thing and parse as another. This body
    // has whitespace that JSON.stringify would never emit; it must still
    // verify, which proves the raw bytes were used.
    const rawBody = '{\n  "action":   "deleted",\n  "installation": { "id": 12345 }\n}';
    const outcome = await handleWebhook(
      deliver(null, { rawBody, signature: signBody(rawBody, SECRET) }),
      deps(),
    );
    expect(outcome.kind).toBe("accepted");
  });

  it("rejects a body altered after signing", async () => {
    const original = JSON.stringify({ action: "suspend", installation: INSTALLATION });
    const tampered = JSON.stringify({ action: "deleted", installation: INSTALLATION });
    const outcome = await handleWebhook(
      { body: tampered, headers: {
          "x-github-event": "installation",
          "x-github-delivery": "12345678-1234-1234-1234-123456789abc",
          "x-hub-signature-256": signBody(original, SECRET),
        } },
      deps(),
    );
    expect(rejection(outcome)).toBe("bad-signature");
  });

  it("rejects an oversized body before hashing it", async () => {
    const outcome = await handleWebhook(
      { body: "x".repeat(2048), headers: {} },
      { ...deps(), maxBodyBytes: 1024 },
    );
    expect(rejection(outcome)).toBe("oversized");
  });
});

describe("replay", () => {
  it("processes a delivery once", async () => {
    const seen = new Set<string>();
    const payload = { action: "deleted", installation: INSTALLATION };

    const first = await handleWebhook(deliver(payload), deps(seen));
    const second = await handleWebhook(deliver(payload), deps(seen));

    expect(first.kind).toBe("accepted");
    expect(second.kind).toBe("duplicate");
  });

  it("claims the delivery before interpreting the payload", async () => {
    // A retry arriving while the first is still in flight must not
    // double-apply. Claiming first means the race is resolved by the claim,
    // not by processing speed.
    const claimed: string[] = [];
    const outcome = await handleWebhook(
      deliver({ action: "not-a-real-action", installation: INSTALLATION }),
      {
        secret: SECRET,
        async claimDelivery(id) {
          claimed.push(id);
          return false;
        },
      },
    );
    expect(claimed).toHaveLength(1);
    expect(outcome.kind).toBe("ignored");
  });

  it("rejects a delivery with no id, since it cannot be deduplicated", async () => {
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }, { deliveryId: null }),
      deps(),
    );
    expect(rejection(outcome)).toBe("missing-delivery-id");
  });

  it("rejects a malformed delivery id", async () => {
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }, {
        deliveryId: "'; DROP TABLE job; --",
      }),
      deps(),
    );
    expect(rejection(outcome)).toBe("missing-delivery-id");
  });

  it("does not claim a delivery whose signature failed", async () => {
    // Otherwise an attacker could burn delivery ids and cause GitHub's genuine
    // retries to be discarded as duplicates.
    let claims = 0;
    await handleWebhook(deliver({ action: "deleted" }, { secret: "wrong" }), {
      secret: SECRET,
      async claimDelivery() {
        claims += 1;
        return false;
      },
    });
    expect(claims).toBe(0);
  });
});

describe("revocation", () => {
  it("recognises an uninstall", async () => {
    // The customer's revocation path. If this is missed we keep acting on an
    // installation they believe they revoked.
    const outcome = await handleWebhook(
      deliver({ action: "deleted", installation: INSTALLATION }),
      deps(),
    );
    expect(outcome).toMatchObject({
      kind: "accepted",
      event: { type: "installation.revoked", installationId: 12345 },
    });
  });

  it("recognises suspension and unsuspension", async () => {
    const suspended = await handleWebhook(
      deliver({ action: "suspend", installation: INSTALLATION }),
      deps(),
    );
    const unsuspended = await handleWebhook(
      deliver({ action: "unsuspend", installation: INSTALLATION }, {
        deliveryId: "22345678-1234-1234-1234-123456789abc",
      }),
      deps(),
    );
    expect(suspended).toMatchObject({ event: { type: "installation.suspended" } });
    expect(unsuspended).toMatchObject({ event: { type: "installation.unsuspended" } });
  });

  it("recognises repositories being withdrawn", async () => {
    const outcome = await handleWebhook(
      deliver(
        {
          action: "removed",
          installation: INSTALLATION,
          repositories_removed: [{ full_name: "Acme/Widgets" }, { full_name: "acme/gadgets" }],
        },
        { event: "installation_repositories" },
      ),
      deps(),
    );
    expect(outcome).toMatchObject({
      kind: "accepted",
      event: {
        type: "repositories.removed",
        repositories: [
          { owner: "acme", name: "widgets" },
          { owner: "acme", name: "gadgets" },
        ],
      },
    });
  });

  it("rejects a repository-removal batch containing a malformed entry", async () => {
    // Partially applying a withdrawal would leave us acting on repositories
    // the customer has taken back.
    const outcome = await handleWebhook(
      deliver(
        {
          action: "removed",
          installation: INSTALLATION,
          repositories_removed: [{ full_name: "acme/widgets" }, { nonsense: true }],
        },
        { event: "installation_repositories" },
      ),
      deps(),
    );
    expect(rejection(outcome)).toBe("unexpected-shape");
  });
});

describe("pull request outcomes", () => {
  it("captures a merge", async () => {
    const outcome = await handleWebhook(
      deliver(
        {
          action: "closed",
          installation: INSTALLATION,
          repository: { full_name: "acme/widgets" },
          pull_request: { number: 42, merged: true },
        },
        { event: "pull_request" },
      ),
      deps(),
    );
    expect(outcome).toMatchObject({
      kind: "accepted",
      event: { type: "pull_request.closed", number: 42, merged: true },
    });
  });

  it("captures a close without merge", async () => {
    // The strongest negative signal we get about migration quality.
    const outcome = await handleWebhook(
      deliver(
        {
          action: "closed",
          installation: INSTALLATION,
          repository: { owner: { login: "Acme" }, name: "Widgets" },
          pull_request: { number: 7, merged: false },
        },
        { event: "pull_request" },
      ),
      deps(),
    );
    expect(outcome).toMatchObject({
      event: { merged: false, repository: { owner: "acme", name: "widgets" } },
    });
  });

  it("ignores pull request actions other than closed", async () => {
    const outcome = await handleWebhook(
      deliver({ action: "opened", installation: INSTALLATION }, { event: "pull_request" }),
      deps(),
    );
    expect(outcome.kind).toBe("ignored");
  });
});

describe("authenticated but malformed", () => {
  it("rejects a valid signature over invalid JSON", async () => {
    const rawBody = "not json at all";
    const outcome = await handleWebhook(
      deliver(null, { rawBody, signature: signBody(rawBody, SECRET) }),
      deps(),
    );
    expect(rejection(outcome)).toBe("unparseable");
  });

  it("rejects a payload with no installation", async () => {
    // Authenticated proves GitHub sent it, not that it has the shape we
    // expect. Fields are checked rather than assumed.
    const outcome = await handleWebhook(deliver({ action: "deleted" }), deps());
    expect(rejection(outcome)).toBe("unexpected-shape");
  });

  it("rejects a non-numeric or hostile installation id", async () => {
    for (const id of ["12345", -1, 0, 1.5, null, {}]) {
      const outcome = await handleWebhook(
        deliver({ action: "deleted", installation: { id } }, {
          deliveryId: "32345678-1234-1234-1234-123456789abc",
        }),
        deps(),
      );
      expect(rejection(outcome), JSON.stringify(id)).toBe("unexpected-shape");
    }
  });

  it("rejects a non-object payload", async () => {
    const rawBody = '"just a string"';
    const outcome = await handleWebhook(
      deliver(null, { rawBody, signature: signBody(rawBody, SECRET) }),
      deps(),
    );
    expect(rejection(outcome)).toBe("unexpected-shape");
  });

  it("ignores event types we have no business reacting to", async () => {
    for (const event of ["star", "watch", "push", "issues", "fork"]) {
      const outcome = await handleWebhook(
        deliver({ action: "created", installation: INSTALLATION }, {
          event,
          deliveryId: "42345678-1234-1234-1234-123456789abc",
        }),
        deps(),
      );
      expect(outcome.kind, event).toBe("ignored");
    }
  });

  it("ignores a delivery with no event type", async () => {
    const raw = deliver({ action: "deleted", installation: INSTALLATION });
    const headers = { ...raw.headers };
    delete headers["x-github-event"];
    const outcome = await handleWebhook({ ...raw, headers }, deps());
    expect(outcome.kind).toBe("ignored");
  });
});
