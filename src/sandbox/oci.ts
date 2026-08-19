/**
 * The OCI bundle a sandboxed test run executes in.
 *
 * Built as a pure function returning the spec object, separately from anything
 * that spawns a process, because the security properties of a sandbox live
 * almost entirely in this configuration — whether the root is read-only,
 * whether the network exists, which capabilities survive — and a configuration
 * that can only be inspected by running gVisor is one nobody reviews.
 *
 * Everything here is a deny-by-default choice, and each one is the difference
 * between a sandbox and a subprocess:
 *
 *   * No network namespace is joined. A test suite has no business reaching
 *     the internet, and the install that does need it is a separate decision
 *     (see `network` below).
 *   * Every capability is dropped. Nothing a test suite legitimately does
 *     needs one.
 *   * `noNewPrivileges`. Without it a setuid binary in the rootfs is an
 *     escalation path that the capability drop above does not close.
 *   * The rootfs is read-only. Only the workspace is writable, so a suite
 *     cannot leave anything behind for the next run in a shared rootfs.
 *   * `/proc` and `/dev` are the minimal masked set. Unmasked `/proc` exposes
 *     the host's kernel interfaces to code we are treating as hostile.
 */

export interface OciConfigOptions {
  /** Absolute host path to the workspace. Mounted read-write at `/work`. */
  readonly workspacePath: string;
  /** Absolute host path to the rootfs (a Node image, see SANDBOX_SETUP.md). */
  readonly rootfsPath: string;
  /** Command and arguments, run from `/work`. */
  readonly command: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  /**
   * Whether the sandbox has a network at all.
   *
   * `none` is the default and the only setting a *test* run should use.
   * Installing dependencies needs a registry, and the honest way to allow that
   * is an egress-proxied namespace restricted to the allowlist in
   * `environment.ts` — which is host provisioning this module cannot assert,
   * so it is a caller's explicit decision rather than a default.
   */
  readonly network?: "none" | "host";
  readonly uid?: number;
  readonly gid?: number;
}

export function buildOciConfig(options: OciConfigOptions): Record<string, unknown> {
  const namespaces: { type: string }[] = [
    { type: "pid" },
    { type: "ipc" },
    { type: "uts" },
    { type: "mount" },
  ];
  // Joining no network namespace at all would inherit the host's. An empty
  // one is the isolated case; omitting the entry is the shared one.
  if ((options.network ?? "none") === "none") namespaces.push({ type: "network" });

  return {
    ociVersion: "1.0.2",
    process: {
      terminal: false,
      // Never root, even inside a sandbox: defence in depth costs nothing here
      // and a container escape lands as an unprivileged user.
      user: { uid: options.uid ?? 1000, gid: options.gid ?? 1000 },
      args: [...options.command],
      env: Object.entries(options.env).map(([key, value]) => `${key}=${value}`),
      cwd: "/work",
      capabilities: {
        bounding: [],
        effective: [],
        inheritable: [],
        permitted: [],
        ambient: [],
      },
      noNewPrivileges: true,
      rlimits: [
        // A fork bomb is the cheapest denial of service available to a test
        // suite, and the timeout does not stop it from taking the host with it.
        { type: "RLIMIT_NPROC", hard: 512, soft: 512 },
        { type: "RLIMIT_NOFILE", hard: 4096, soft: 4096 },
        { type: "RLIMIT_FSIZE", hard: 1_073_741_824, soft: 1_073_741_824 },
      ],
    },
    root: { path: options.rootfsPath, readonly: true },
    hostname: "driftless",
    mounts: [
      { destination: "/work", type: "bind", source: options.workspacePath, options: ["rbind", "rw", "nosuid", "nodev"] },
      { destination: "/proc", type: "proc", source: "proc" },
      { destination: "/dev", type: "tmpfs", source: "tmpfs", options: ["nosuid", "strictatime", "mode=755", "size=65536k"] },
      { destination: "/tmp", type: "tmpfs", source: "tmpfs", options: ["nosuid", "nodev", "mode=1777", "size=256m"] },
    ],
    linux: {
      namespaces,
      maskedPaths: [
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/sched_debug",
        "/sys/firmware",
      ],
      readonlyPaths: ["/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
    },
  };
}
