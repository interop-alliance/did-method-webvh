import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Some tests perform real Ed25519 signing across multiple DID operations,
    // so allow generous timeouts over the defaults.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      // Informational only -- no thresholds.
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'html'],
    },
  },
});
