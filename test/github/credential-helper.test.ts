import { describe, expect, it } from "vitest";
import {
  CredentialHelper,
  gitCredentialArgs,
  parseCredentialRequest,
  type HelperOutcome,
} from "../../src/github/credential-helper.ts";
import { ScopedToken, REQUIRED_PERMISSIONS } from "../../src/github/token.ts";

/**
 * Credential helper scoping (ADR-0002 §5).
 *
 * The helper is the only place in the system where a credential is handed to
 * a process that talks to the network on behalf of a repository we do not
 * trust. There is no control behind it — if it answers the wrong request, the
 * token is gone, and git performs the exfiltration over a connection the
 * egress allowlist considers legitimate.
 *
 * So these tests are written as an attacker trying to get the token out.
 */

const SECRET = "ghs_TESTTOKENvalue0000000000000000000000";

function token(ttlSeconds = 300): ScopedToken {
  return new ScopedToken(
    SECRET,
    {
      repositoryId: "repo-1",
      installationId: "inst-1",
      permissions: REQUIRED_PERMISSIONS,
    },
    new Date(Date.now() + ttlSeconds * 1000),
    "tok_abc123",
  );
}

function helper(ttlSeconds = 300): CredentialHelper {
  return new CredentialHelper(token(ttlSeconds), {
    host: "github.com",
    repositoryPath: "acme/widgets",
  });
}

function refusal(outcome: HelperOutcome): string {
  return outcome.kind === "refused" ? outcome.reason : `not-refused(${outcome.kind})`;
}

describe("the legitimate request", () => {
  it("supplies credentials for its own repository", () => {
    const outcome = helper().handle("get", {
      protocol: "https",
      host: "github.com",
      path: "acme/widgets",
    });
    expect(outcome.kind).toBe("credentials");
    if (outcome.kind !== "credentials") return;
    expect(outcome.output).toBe(`username=x-access-token\npassword=${SECRET}\n`);
  });

  it("tolerates the .git suffix and a leading slash", () => {
    for (const path of ["/acme/widgets.git", "acme/widgets.git", "/acme/widgets"]) {
      expect(
        helper().handle("get", { protocol: "https", host: "github.com", path }).kind,
        path,
      ).toBe("credentials");
    }
  });

  it("matches host and path case-insensitively", () => {
    const outcome = helper().handle("get", {
      protocol: "https",
      host: "GitHub.com",
      path: "Acme/Widgets",
    });
    expect(outcome.kind).toBe("credentials");
  });
});

describe("exfiltration attempts", () => {
  it("refuses a different repository on the same host", () => {
    // The submodule attack. A hostile .gitmodules points at a repository the
    // attacker controls; git dutifully asks us for credentials for it. Host
    // matching alone would authorise this, and the egress allowlist would
    // permit the connection — it is github.com either way.
    const outcome = helper().handle("get", {
      protocol: "https",
      host: "github.com",
      path: "attacker/collector",
    });
    expect(refusal(outcome)).toBe("path-mismatch");
  });

  it("refuses a request with no path at all", () => {
    // Without credential.useHttpPath git omits the path. A helper that treated
    // that as a host-level match would authorise every repository on
    // github.com — which is the same compromise as the case above, reached by
    // configuration rather than by content.
    const outcome = helper().handle("get", { protocol: "https", host: "github.com" });
    expect(refusal(outcome)).toBe("path-missing");
  });

  it("refuses a different host", () => {
    const outcome = helper().handle("get", {
      protocol: "https",
      host: "github.evil.example",
      path: "acme/widgets",
    });
    expect(refusal(outcome)).toBe("host-mismatch");
  });

  it("refuses a host that merely contains the real one", () => {
    for (const host of [
      "github.com.evil.example",
      "evil-github.com",
      "github.com.",
      "wwwgithub.com",
    ]) {
      expect(
        refusal(helper().handle("get", { protocol: "https", host, path: "acme/widgets" })),
        host,
      ).toBe("host-mismatch");
    }
  });

  it("refuses a path that merely starts with the real one", () => {
    for (const path of [
      "acme/widgets-exfil",
      "acme/widgets/../../attacker/collector",
      "acme/widgetsx",
    ]) {
      expect(
        refusal(
          helper().handle("get", { protocol: "https", host: "github.com", path }),
        ),
        path,
      ).toBe("path-mismatch");
    }
  });

  it("refuses to downgrade to http", () => {
    // An insteadOf rule or a rewritten remote can ask for this. Answering
    // would put the token on the wire in cleartext.
    const outcome = helper().handle("get", {
      protocol: "http",
      host: "github.com",
      path: "acme/widgets",
    });
    expect(refusal(outcome)).toBe("insecure-protocol");
  });

  it("refuses a request with no host", () => {
    expect(refusal(helper().handle("get", { protocol: "https", path: "acme/widgets" }))).toBe(
      "malformed-request",
    );
  });

  it("refuses once the token has expired", () => {
    const outcome = helper(-1).handle("get", {
      protocol: "https",
      host: "github.com",
      path: "acme/widgets",
    });
    expect(refusal(outcome)).toBe("token-expired");
  });

  it("never emits the secret in a refusal", () => {
    // Refusal detail is written to stderr, which lands in job logs.
    const attempts: Parameters<CredentialHelper["handle"]>[1][] = [
      { protocol: "https", host: "github.com", path: "attacker/collector" },
      { protocol: "http", host: "github.com", path: "acme/widgets" },
      { protocol: "https", host: "evil.example", path: "acme/widgets" },
      { protocol: "https", host: "github.com" },
    ];
    for (const attempt of attempts) {
      const outcome = helper().handle("get", attempt);
      expect(outcome.kind).toBe("refused");
      if (outcome.kind !== "refused") continue;
      expect(outcome.detail).not.toContain(SECRET);
      expect(outcome.detail).not.toContain("ghs_");
    }
  });
});

describe("store and erase are inert", () => {
  it("writes nothing on store", () => {
    // Implementing store would persist a credential to disk — standing
    // privilege, which is the thing ADR-0002 exists to eliminate.
    expect(
      helper().handle("store", {
        protocol: "https",
        host: "github.com",
        path: "acme/widgets",
      }).kind,
    ).toBe("no-output");
  });

  it("writes nothing on erase", () => {
    expect(
      helper().handle("erase", {
        protocol: "https",
        host: "github.com",
        path: "acme/widgets",
      }).kind,
    ).toBe("no-output");
  });

  it("refuses an unknown operation", () => {
    expect(
      refusal(
        helper().handle("wipe" as never, { protocol: "https", host: "github.com" }),
      ),
    ).toBe("unsupported-operation");
  });
});

describe("request parsing", () => {
  it("parses git's key=value protocol", () => {
    const parsed = parseCredentialRequest(
      "protocol=https\nhost=github.com\npath=acme/widgets\nusername=x-access-token\n",
    );
    expect(parsed).toEqual({
      protocol: "https",
      host: "github.com",
      path: "acme/widgets",
      username: "x-access-token",
    });
  });

  it("ignores unknown and array-valued keys rather than failing", () => {
    // Git adds keys over releases. A helper that rejects unrecognised ones
    // breaks on upgrade, and a broken helper gets replaced with a worse one.
    const parsed = parseCredentialRequest(
      "protocol=https\nhost=github.com\npath=acme/widgets\nwwwauth[]=Basic\ncapability[]=authtype\nfuture=x\n",
    );
    expect(parsed.host).toBe("github.com");
    expect(parsed.path).toBe("acme/widgets");
  });

  it("takes the last value for a duplicated key", () => {
    // Matches git's behaviour. Taking the first would let an attacker prepend
    // a legitimate path ahead of the one git is actually connecting to.
    const parsed = parseCredentialRequest(
      "host=github.com\npath=acme/widgets\npath=attacker/collector\n",
    );
    expect(parsed.path).toBe("attacker/collector");
    expect(refusal(helper().handle("get", parsed))).toBe("path-mismatch");
  });

  it("survives a value containing an equals sign", () => {
    const parsed = parseCredentialRequest("host=github.com\npath=acme/wid=gets\n");
    expect(parsed.path).toBe("acme/wid=gets");
  });
});

describe("git invocation", () => {
  it("clears inherited helpers before installing ours", () => {
    // An empty credential.helper resets the list. Without it, a helper from
    // the environment or a global config still gets asked, and may answer.
    const args = gitCredentialArgs("/usr/local/bin/git-credential-driftless");
    const helperValues = args.filter((_, i) => args[i - 1] === "-c");
    expect(helperValues[0]).toBe("credential.helper=");
    expect(helperValues[1]).toContain("git-credential-driftless");
  });

  it("enables useHttpPath, without which scoping cannot work", () => {
    expect(gitCredentialArgs("x")).toContain("credential.useHttpPath=true");
  });

  it("restricts protocols and disables submodule recursion", () => {
    const args = gitCredentialArgs("x");
    expect(args).toContain("protocol.allow=never");
    expect(args).toContain("protocol.https.allow=always");
    expect(args).toContain("submodule.recurse=false");
  });

  it("is passed as argv, never written to .git/config", () => {
    // Configuration on disk is readable by the agent and overridable by
    // committed repository config. Command-line -c wins and leaves nothing
    // behind.
    const args = gitCredentialArgs("x");
    expect(args.filter((a) => a === "-c").length).toBeGreaterThanOrEqual(6);
    expect(args.every((a) => !a.includes("\n"))).toBe(true);
  });
});
