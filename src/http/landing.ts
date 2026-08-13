/**
 * The public homepage.
 *
 * Served by the same process as the webhook receiver and the opt-out page, so
 * there is no second host to run. It is also the GitHub App's homepage URL,
 * which matters more than it looks: a maintainer who receives an unsolicited
 * pull request clicks through to find out who sent it, and what they find at
 * that moment decides whether the pull request gets read or closed.
 *
 * So this page answers the three questions someone asks in that order:
 *
 *   1. What just opened a pull request in my repository?
 *   2. Why did it think that was appropriate?
 *   3. How do I make it stop?
 *
 * The third is answered without requiring an account, an email, or a
 * conversation — consistent with the promise in every pull request body. A
 * homepage that buries the off switch is worse than one that has none, because
 * it is the same page that claims to have one.
 *
 * Static, self-contained, no external requests. It is the most-fetched
 * unauthenticated route we expose, and a homepage that loads a font from a CDN
 * is a homepage that leaks its visitors to that CDN.
 */

export interface LandingContent {
  /** Used for the opt-out instructions. Never interpolated unescaped. */
  readonly publicOrigin: string;
}

const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "public, max-age=300",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
});

export function landingResponse(): {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: string;
} {
  return { status: 200, headers: SECURITY_HEADERS, body: PAGE };
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Driftless</title>
<meta name="description" content="Driftless detects breaking changes in upstream APIs and opens the fixing pull request in downstream codebases.">
<style>
  :root { color-scheme: light dark; --fg: #16161a; --muted: #5b5b66; --bg: #fdfdfd; --line: #e4e4e8; --accent: #1a5fb4; }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #e8e8ea; --muted: #a0a0ac; --bg: #131316; --line: #2a2a30; --accent: #7aa8e8; }
  }
  * { box-sizing: border-box; }
  body {
    font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    color: var(--fg); background: var(--bg);
    max-width: 42rem; margin: 0 auto; padding: 4rem 1.25rem 6rem;
  }
  h1 { font-size: 1.6rem; letter-spacing: -0.02em; margin: 0 0 .4rem; }
  .tagline { color: var(--muted); margin: 0 0 3rem; font-size: 1.05rem; }
  h2 { font-size: 1.05rem; margin: 2.75rem 0 .75rem; letter-spacing: -0.01em; }
  p { margin: 0 0 1rem; }
  a { color: var(--accent); }
  ul { padding-left: 1.1rem; margin: 0 0 1rem; }
  li { margin-bottom: .4rem; }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em;
    background: color-mix(in srgb, var(--fg) 7%, transparent);
    padding: .12em .35em; border-radius: 3px;
  }
  .callout {
    border: 1px solid var(--line); border-left: 3px solid var(--accent);
    border-radius: 4px; padding: 1rem 1.25rem; margin: 1.25rem 0;
    background: color-mix(in srgb, var(--fg) 3%, transparent);
  }
  .callout h2 { margin-top: 0; }
  footer { margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .9rem; }
</style>
</head>
<body>

<h1>Driftless</h1>
<p class="tagline">Detects breaking changes in upstream APIs and opens the fixing pull request in downstream codebases.</p>

<div class="callout">
  <h2>Got a pull request you didn't ask for?</h2>
  <p>Every pull request Driftless opens carries an opt-out link in its
     description. One click, no account, no email — and we will not open
     another one in that repository.</p>
  <p>If you'd rather not hunt for the link, close the pull request with a
     comment saying so. That works too.</p>
</div>

<h2>What it does</h2>
<p>When a package you depend on ships a breaking change, you usually find out
   in one of two ways: your build breaks, or it doesn't — and you quietly stay
   on a version that stops receiving fixes. Driftless watches for those changes
   and prepares the migration ahead of you.</p>
<ul>
  <li>Detects the change from registry metadata, the published artifact, and
      the package's own type declarations — never from a changelog alone.</li>
  <li>Works out which repositories are actually affected, and whether they are
      stranded on an old version or exposed to the new one.</li>
  <li>Generates the migration and runs the repository's own test suite
      against it.</li>
  <li>Opens a pull request explaining what changed and what was verified.</li>
</ul>

<h2>What it will not do</h2>
<p>These are enforced by the system rather than promised by it.</p>
<ul>
  <li><strong>It cannot merge anything.</strong> The app holds
      <code>contents:write</code> and <code>pull_requests:write</code> and no
      other permission. Your review is a control, not a formality.</li>
  <li><strong>It does not touch unrelated files.</strong> Edits outside the
      API surface the upstream change affected are rejected before a pull
      request is opened.</li>
  <li><strong>It does not add dependencies, network calls, or CI changes.</strong>
      Those are never generated automatically.</li>
  <li><strong>It does not keep your code.</strong> Repositories are cloned into
      a single-use sandbox and destroyed with it.</li>
  <li><strong>It has no standing access.</strong> Credentials are issued per
      job, scoped to one repository, and expire in minutes.</li>
</ul>

<h2>Security</h2>
<p>Driftless reads repositories it does not own, executes untrusted code, and
   writes to codebases at scale. That combination is worth being careful about,
   and the architecture is designed around it rather than hardened afterwards.</p>
<p>If you have found a security problem, please report it privately before
   disclosing it publicly. We would much rather hear from you first.</p>

<footer>
  Driftless opens pull requests. It never merges them.
</footer>

</body>
</html>`;
