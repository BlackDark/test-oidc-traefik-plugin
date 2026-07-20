import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 60_000,
  use: {
    trace: 'on-first-retry',
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'mock-oidc',
      testDir: './tests/mock-oidc',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'keycloak',
      testDir: './tests/keycloak',
      testMatch: /tls\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
