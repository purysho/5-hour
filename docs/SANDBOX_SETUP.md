# Sandbox Setup: gVisor Implementation

The test verification sandbox is implemented via [gVisor](https://gvisor.dev/), an open-source container sandbox that intercepts and emulates Linux syscalls. This provides OS-level isolation for running untrusted test suites without requiring host virtualization features like KVM.

## Architecture

When `migrate-repository` generates a migration:

1. **Agent generates** the diff against the impacted files
2. **Verifier runs** the repository's test suite inside a gVisor sandbox
   - Repository is copied into a temporary directory inside the sandbox
   - Dependencies are installed (npm, pnpm, yarn, etc.)
   - Test command is executed (`npm test`, `pnpm test`, or detected equivalent)
   - Output and exit code are captured
3. **Result is reported** as one of: `passed`, `failed`, `not-run`, or `error`
4. **PR body** includes test verification status

This ensures:
- **Isolation**: Tests cannot escape to the control plane
- **Honesty**: Tests reported as "passed" actually ran and passed (ADR-0006)
- **Safety**: Running arbitrary test commands is safe because the sandbox bounds them

## Status

The verifier and the workspace are implemented (`src/sandbox/`). What remains
is host provisioning, and it is why a worker on a managed container platform
still reports `tests: not-run`:

| Piece | State |
| --- | --- |
| Workspace — clone, overlay the migration, dispose | **done** (`workspace.ts`) |
| OCI bundle, deny-by-default | **done** (`oci.ts`) |
| Verdict from exit code, refusal without a sandbox | **done** (`gvisor-verifier.ts`) |
| `runsc` + rootfs on the host | **not provisioned** |
| Egress-proxied network for the dependency install | **not built** |

Two consequences worth stating plainly:

- **Railway (and most managed container platforms) cannot host this.** `runsc`
  needs either KVM or `ptrace` with capabilities a managed container does not
  grant. The verifying worker needs a VM you control, which is a deployment
  change, not a code change.
- **Until the egress proxy exists, only a repository whose suite runs without
  installing anything can be verified.** The install step defaults to no
  network, and a failed install reports `not-run` rather than `failed` — our
  missing policy must never be rendered as the customer's tests breaking.

gVisor's own isolation is not exercised by the test suite: there is no `runsc`
in CI, so the process runner is injected and what the tests assert is the
decision-making around it (exit-code verdicts, refusing to run unsandboxed,
never blaming the diff for our infrastructure). Treat the escape properties as
unverified from this repository until it has run on a provisioned host.

## Prerequisites

### Host Requirements

The worker must run on a Linux host with the following:

1. **gVisor runtime** (`runsc` binary)
   ```bash
   # Install gVisor (Ubuntu/Debian)
   curl -fsSL https://gvisor.dev/archive.key | sudo apt-key add -
   sudo add-apt-repository "deb https://storage.googleapis.com/gvisor/releases release main"
   sudo apt-get update
   sudo apt-get install -y runsc
   
   # Or download binary directly
   curl -L https://releases.gvisor.dev/latest/x86_64/runsc > runsc
   chmod +x runsc
   sudo mv runsc /usr/local/bin/
   ```

2. **Container runtime** (runc or crun) for OCI bundle execution
   ```bash
   # Ubuntu/Debian
   sudo apt-get install -y runc
   ```

3. **Container image or rootfs**
   - Minimal Node.js image (e.g., `node:20-slim`)
   - ~200MB to ~500MB uncompressed
   - Should include package managers: npm, pnpm, yarn

### Worker Configuration

The worker should have `GVISOR_AVAILABLE=true` in its environment to enable verification. If not set or set to `false`, the verifier returns `not-run` to maintain honest reporting.

## Rootfs Preparation

Two approaches:

### Option 1: Use OCI Image (Recommended)

Extract a standard Node.js Docker image into a rootfs directory:

```bash
docker export $(docker create node:20-slim) | tar -x -C /opt/driftless/rootfs
```

### Option 2: Build Minimal Rootfs

Create a minimal rootfs with only what's needed:

```bash
# Using debootstrap (Debian/Ubuntu)
sudo debootstrap --include=ca-certificates,curl,git,nodejs,npm,pnpm focal /opt/driftless/rootfs http://archive.ubuntu.com/ubuntu/

# Or use a pre-built slim image
mkdir -p /opt/driftless/rootfs
docker export $(docker create node:20-alpine) | tar -x -C /opt/driftless/rootfs
```

Configure `/opt/driftless/rootfs/etc/profile` to include:
- `PATH` pointing to `/usr/local/bin:/usr/bin:/bin`
- `NODE_ENV=test` to disable dev dependencies optimizations
- Any required proxies or credentials (for private npm registries)

## Test Discovery

The verifier attempts to find the test command in this order:

1. **package.json** → `scripts.test` field
   ```json
   {
     "scripts": {
       "test": "vitest run"
     }
   }
   ```

2. **Makefile** → `test` target
   ```makefile
   test:
   	npm test
   ```

3. **shell script** → `test.sh`, `runtests.sh`, etc.

If no test command is found, the verifier returns `not-run`.

## Timeout and Resource Limits

Tests are executed with:

- **Timeout**: 5 minutes (300 seconds)
  - Can be configured via `SANDBOX_TIMEOUT_MS` environment variable
  - Tests exceeding timeout are marked as `failed`

- **Memory limit**: 2GB (configurable)
  - Out-of-memory is treated as test failure

- **CPU limit**: Cgroup-based (typically 1-2 vCPU)
  - Prevents resource exhaustion

## Implementation Status

**Current**: Verifier scaffold is in place (`GVisorVerifier` class) but the actual gVisor integration is not yet implemented. The verifier currently returns `not-run` to maintain honest reporting.

**Next step**: Implement `runInGVisor()` function in `src/sandbox/gvisor-verifier.ts`:

```typescript
async function runInGVisor(input: {
  rootfs: string;
  repository: string;
  command: string;
  timeoutMs: number;
}): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
  durationSeconds: number;
}>
```

This function should:

1. Create an OCI bundle directory with `config.json`
2. Mount the repository at `/work`
3. Create a container via `runsc create`
4. Execute `command` inside via `runsc exec`
5. Capture stdout/stderr
6. Clean up the bundle

## Testing

To test the sandbox locally without gVisor installed:

```bash
# Set GVISOR_AVAILABLE=false to use stub
GVISOR_AVAILABLE=false pnpm test test/agent/claude-migration-agent.test.ts

# Set GVISOR_AVAILABLE=true to use gVisor (requires gVisor installed)
GVISOR_AVAILABLE=true pnpm test test/agent/claude-migration-agent.test.ts
```

## Security Considerations

- **Escape prevention**: gVisor intercepts all syscalls, preventing kernel exploits
- **Resource bounds**: Memory/CPU limits prevent DoS
- **Network isolation**: Sandbox has no network access by default
  - To enable (e.g., for private npm registries): mount `/etc/resolv.conf` and configure network policy
- **Filesystem isolation**: Mounts are read-only except for `/work` (test directory)

## See Also

- [ADR-0006: Sandbox Requirement for Test Verification](./ARCHITECTURE.md#adr-0006)
- [gVisor Documentation](https://gvisor.dev/)
- [OCI Image Spec](https://github.com/opencontainers/image-spec)
