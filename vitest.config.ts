import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // cli-e2e spawns ~20 tsx subprocesses, each paying TS transform +
    // key generation cost, so the defaults are too tight.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
