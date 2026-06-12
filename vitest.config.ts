import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // cli-e2e spawns ~20 tsx subprocesses, each paying TS transform +
    // key generation cost, so the defaults are too tight.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      // Informational only -- no thresholds. The CLI is exercised through
      // tsx subprocesses in cli-e2e.test.ts, which V8 coverage cannot see,
      // so enforced minimums would misrepresent actual coverage.
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'html'],
    },
  },
});
