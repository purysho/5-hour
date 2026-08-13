import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Schema reset and role creation happen once, before any worker starts.
    // Per-file setup would race across worker threads.
    globalSetup: ["test/global-setup.ts"],
    // Database-backed tests share one Postgres instance and manipulate
    // session-level tenant context. Running them in parallel across threads
    // is safe (separate connections) but tests that assert on global table
    // state are marked sequential individually.
    pool: "threads",
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
