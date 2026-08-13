import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Schema reset and role creation happen once, before any worker starts.
    // Per-file setup would race across worker threads.
    globalSetup: ["test/global-setup.ts"],
    pool: "threads",
    // Test FILES run one at a time.
    //
    // The suite shares a single Postgres instance by design (ADR-0004,
    // ADR-0005 — mocking the database would test the mock). Most state is
    // tenant-scoped and safe to run in parallel, but some is deliberately
    // global: `outbound_kill_switch` is one row for the whole platform, so a
    // file that halts it changes what every other file sees.
    //
    // That produced a genuine, order-dependent flake. Serialising files costs
    // about a second on a four-second suite, which is a trade worth making —
    // the alternative is per-test advisory locking that every future test
    // would have to remember to use.
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts", "src/**/index.ts"],
      thresholds: {
        // ADR-0008 lists coverage enforcement as build-from-the-start.
        // Raise these as the surface grows; never lower them to make a
        // build pass.
        lines: 85,
        functions: 85,
        branches: 80,
        statements: 85,
      },
    },
  },
});
