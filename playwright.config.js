// End-to-end tests: Playwright starts the real server (with a throw-away in-memory database) and drives a real browser.
const { defineConfig, devices } = require('@playwright/test');

const PORT = 3100;
module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30000,
  expect: { timeout: 7000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: 'http://localhost:' + PORT,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node server/index.js',
    url: 'http://localhost:' + PORT + '/api/session',
    reuseExistingServer: !process.env.CI,
    env: { PORT: String(PORT), DB_FILE: ':memory:', BCRYPT_COST: '4', NODE_ENV: 'test' }
  }
});
