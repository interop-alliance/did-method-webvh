// Helper to safely access environment variables
const isBrowser = typeof window !== 'undefined';

const getEnvValue = (key: string): string | undefined => {
  if (isBrowser) return undefined;
  try {
    return process?.env?.[key];
  } catch {
    return undefined;
  }
};

export const config = {
  // Helper functions
  getEnvValue,
  isBrowser,

  // Environment checks
  isTestEnvironment: getEnvValue('NODE_ENV') === 'test',

  // Feature flags
  logResolves: getEnvValue('LOG_RESOLVES') === 'true',
};
