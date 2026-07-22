import fs from 'node:fs';
import path from 'node:path';
import { expect, type Page, type Response, test } from '@playwright/test';
import * as dockerCompose from 'docker-compose';
import { configureTraefik } from '../../utils';

test.use({
  ignoreHTTPSErrors: true,
});

test.beforeAll('Starting keycloak', async () => {
  test.setTimeout(300000);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTP}"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await dockerCompose.upAll({
    cwd: __dirname,
    log: true,
    commandOptions: ['--wait', '--wait-timeout', '180'],
  });
});

// biome-ignore lint/correctness/noEmptyPattern: Playwright fixture API
test.afterEach('Traefik logs on test failure', async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await dockerCompose.logs('traefik', { cwd: __dirname }));
    console.log(await dockerCompose.logs('keycloak', { cwd: __dirname }));
  }
});

test.afterAll('Stopping keycloak', async () => {
  await dockerCompose.downAll({
    cwd: __dirname,
    log: true,
  });
});

test('login at provider via self signed certificate from file', async ({ page }) => {
  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTPS}"
            cABundleFile: "/certificates/bundle/ca_bundle.pem"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await expectGotoOkay(page, 'https://localhost:9443');
  const response = await login(page, 'admin', 'admin', 'https://localhost:9443');
  expect(response.status()).toBe(200);
});

test('login at provider via self signed inline certificate', async ({ page }) => {
  const certBundle = fs.readFileSync(path.join(__dirname, './certificates/bundle/ca_bundle.pem'));
  const base64CertBundle = certBundle.toString('base64');

  await configureTraefik(`
http:
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80

  middlewares:
    oidc-auth:
      plugin:
        traefik-oidc-auth:
          logLevel: DEBUG
          secret: "0123456789abcdef0123456789abcdef"
          provider:
            url: "\${PROVIDER_URL_HTTPS}"
            cABundle: "base64:${base64CertBundle}"
            clientId: "\${CLIENT_ID}"
            clientSecret: "\${CLIENT_SECRET}"
            usePkce: false

  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ["oidc-auth@file"]
`);

  await expectGotoOkay(page, 'https://localhost:9443');
  const response = await login(page, 'admin', 'admin', 'https://localhost:9443');
  expect(response.status()).toBe(200);
});

async function login(
  page: Page,
  username: string,
  password: string,
  waitForUrl: string,
): Promise<Response> {
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  const responsePromise = page.waitForResponse(waitForUrl);
  await page.locator('#kc-login').click();
  return responsePromise;
}

async function expectGotoOkay(page: Page, url: string) {
  const response = await page.goto(url);
  expect(response?.status()).toBe(200);
}
