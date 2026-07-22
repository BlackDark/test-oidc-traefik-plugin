import { expect, type Page, type Response, test } from '@playwright/test';
import * as dockerCompose from 'docker-compose';
import { configureTraefik } from '../../utils';

const PROVIDER = 'http://localhost:8000/default';
const AUTH_URL = /http:\/\/localhost:8000\/default\/authorize.*/;
const PLUGIN_SECRET = '0123456789abcdef0123456789abcdef';

function baseMiddleware(extra = ''): string {
  return `
        traefik-oidc-auth:
          LogLevel: DEBUG
          Secret: "${PLUGIN_SECRET}"
          Provider:
            Url: "\${PROVIDER_URL}"
            ClientId: "\${CLIENT_ID}"
            ClientSecret: "\${CLIENT_SECRET}"
            UsePkce: false
${extra}`;
}

function whoamiService(): string {
  return `
  services:
    whoami:
      loadBalancer:
        servers:
          - url: http://whoami:80`;
}

function whoamiRouter(middlewares = '["oidc-auth@file"]'): string {
  return `
  routers:
    whoami:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ${middlewares}
    whoami-secure:
      entryPoints: ["websecure"]
      tls: {}
      rule: "PathPrefix(\`/\`)"
      service: whoami
      middlewares: ${middlewares}`;
}

test.use({
  ignoreHTTPSErrors: true,
});

test.beforeAll('Starting stack', async () => {
  test.setTimeout(120000);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware()}

${whoamiRouter()}
`);

  await dockerCompose.upAll({
    cwd: __dirname,
    log: true,
    commandOptions: ['--wait', '--wait-timeout', '60'],
  });
});

// biome-ignore lint/correctness/noEmptyPattern: Playwright fixture API
test.afterEach('Traefik logs on test failure', async ({}, testInfo) => {
  if (testInfo.status !== testInfo.expectedStatus) {
    console.log(`${testInfo.title} failed, here are Traefik logs:`);
    console.log(await dockerCompose.logs('traefik', { cwd: __dirname }));
    console.log(await dockerCompose.logs('mock-oauth2-server', { cwd: __dirname }));
  }
});

test.afterAll('Stopping stack', async () => {
  await dockerCompose.downAll({
    cwd: __dirname,
    log: true,
  });
});

test.beforeEach(async ({ context }) => {
  await context.clearCookies();
});

test('login http', async ({ page }) => {
  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(page, 'admin', 'admin', 'http://localhost:9080');
  expect(response.status()).toBe(200);
});

test('login https', async ({ page }) => {
  await expectGotoOkay(page, 'https://localhost:9443');
  const response = await login(page, 'admin', 'admin', 'https://localhost:9443');
  expect(response.status()).toBe(200);
});

test('logout', async ({ page }) => {
  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(page, 'admin', 'admin', 'http://localhost:9080');
  expect(response.status()).toBe(200);

  const logoutResponse = await page.goto('http://localhost:9080/logout');
  expect(logoutResponse?.url()).toMatch(AUTH_URL);
});

test('test two services is seamless', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware()}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(page, 'admin', 'admin', 'http://localhost:9080');
  expect(response.status()).toBe(200);

  await expectGotoOkay(page, 'https://localhost:9443');
  await expect(page.getByText(/Hostname:/i)).toBeVisible();
});

test('test headers', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          Headers:
            - Name: "Authorization"
              Value: "{{\`Bearer: {{ .accessToken }}\`}}"
            - Name: "X-Static-Header"
              Value: "42"
`)}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(page, 'admin', 'admin', 'http://localhost:9080');
  expect(response.status()).toBe(200);

  expect(await page.locator('text=Authorization: Bearer: ey').isVisible()).toBeTruthy();
  expect(await page.locator('text=X-Static-Header: 42').isVisible()).toBeTruthy();

  const pageText = await page.innerText('html');
  expect(pageText).not.toMatch(/Cookie:\s*(?:^|\s|;)\s*Authorization\s*=\s*[^;\r\n]+/);
});

test('test authorization', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin", "alice@example.com"]
`)}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(page, 'alice@example.com', 'alice123', 'http://localhost:9080');
  expect(response.status()).toBe(200);
});

test('test authorization failing', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin", "alice@example.com"]
`)}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(
    page,
    'bob@example.com',
    'bob123',
    /http:\/\/localhost:9080\/oidc\/callback/,
    [403],
  );
  expect(response.status()).toBe(403);
  expect(await response.text()).toContain(
    'It seems like your account is not allowed to access this resource.',
  );
});

test('access app with bypass rule', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          LoginUri: "/login"
          BypassAuthenticationRule: "Header(\`MY-HEADER\`, \`123\`)"
`)}

${whoamiRouter()}
`);

  const bypassed = await page.request.get('http://localhost:9080/test1', {
    headers: { 'MY-HEADER': '123' },
  });
  expect(bypassed.status()).toBe(200);
  expect(await bypassed.text()).toMatch(/Hostname:/i);
  expect(await bypassed.text()).toMatch(/MY-HEADER:\s*123/i);

  const blocked = await page.request.get('http://localhost:9080/test2', {
    headers: { 'MY-HEADER': '456' },
    maxRedirects: 0,
  });
  expect([302, 401]).toContain(blocked.status());
});

test('access app with bypass rule and unauthenticated forward', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          BypassAuthenticationRule: "Path(\`/test1\`)"
          UnauthorizedBehavior: Forward
          LoginUri: "/login"
          Headers:
            - Name: "Authorization"
              Value: "{{\`Bearer: {{ .accessToken }}\`}}"
              IncludeWhen: "Public"
`)}

${whoamiRouter()}
`);

  const unauthResponse = await page.goto('http://localhost:9080/test1');
  expect(unauthResponse?.status()).toBe(200);
  expect(await page.locator('text=Authorization: Bearer: ey').isVisible()).toBeFalsy();

  await expectGotoOkay(page, 'http://localhost:9080/login');
  await login(page, 'admin', 'admin', 'http://localhost:9080');
  expect(await page.locator('text=Authorization: Bearer: ey').isVisible()).toBeTruthy();
});

test('external authentication', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          AuthorizationHeader:
            Name: "CustomAuth"
          AuthorizationCookie:
            Name: "CustomAuth"
          UnauthorizedBehavior: "Unauthorized"
`)}

${whoamiRouter()}
`);

  const token = await loginAndGetToken('admin');

  expect((await fetch('http://localhost:9080')).status).toBe(401);
  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { CustomAuth: token },
      })
    ).status,
  ).toBe(200);
  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { CustomAuth: 'wrong value' },
      })
    ).status,
  ).toBe(401);
  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { Cookie: `CustomAuth=${token}` },
      })
    ).status,
  ).toBe(200);
  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { Cookie: 'CustomAuth=wrong' },
      })
    ).status,
  ).toBe(401);

  // silence unused page lint while keeping playwright fixture
  expect(page).toBeTruthy();
});

test('external authentication with authorization rules', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          AuthorizationHeader:
            Name: "CustomAuth"
          UnauthorizedBehavior: "Unauthorized"
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin", "alice@example.com"]
`)}

${whoamiRouter()}
`);

  const aliceToken = await loginAndGetToken('alice@example.com');
  const bobToken = await loginAndGetToken('bob@example.com');

  // Ensure middleware reload finished before probing.
  await new Promise((r) => setTimeout(r, 500));

  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { CustomAuth: aliceToken },
      })
    ).status,
  ).toBe(200);

  expect(
    (
      await fetch('http://localhost:9080', {
        headers: { CustomAuth: bobToken },
      })
    ).status,
  ).toBe(403);

  expect(page).toBeTruthy();
});

test('test authorization custom error page', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin", "alice@example.com"]
          ErrorPages:
            Unauthorized:
              FilePath: "/data/customUnauthorizedPage.html"
`)}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  const response = await login(
    page,
    'bob@example.com',
    'bob123',
    /http:\/\/localhost:9080\/oidc\/callback/,
    [403],
  );
  expect(response.status()).toBe(403);
  expect(await response.text()).toContain('CUSTOM ERROR PAGE');
});

test('test authorization error redirect', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    oidc-auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["admin", "alice@example.com"]
          ErrorPages:
            Unauthorized:
              RedirectTo: "http://localhost:9080/unauthorized"
`)}

${whoamiRouter()}
`);

  await expectGotoOkay(page, 'http://localhost:9080');
  await page.locator('#username').waitFor({ state: 'visible' });
  await page.locator('#username').fill('bob@example.com');
  await page.locator('#password').fill('bob123');

  const redirected = page.waitForResponse(
    (response) =>
      response.status() === 302 && (response.headers().location || '').includes('/unauthorized'),
  );
  await page.locator('#kc-login').click();
  const response = await redirected;
  expect(response.status()).toBe(302);
  expect(await response.headerValue('Location')).toBe('http://localhost:9080/unauthorized');
});

test('test CheckOnEveryRequest', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com", "alice@example.com"]
            CheckOnEveryRequest: true
`)}
    auth-bob:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com"]
            CheckOnEveryRequest: true
`)}
    auth-alice:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["alice@example.com"]
            CheckOnEveryRequest: true
`)}

  routers:
    oidc-callback:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/oidc/callback\`)"
      service: noop@internal
      middlewares: ["auth"]
    whoami-bob:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/bob\`)"
      service: whoami
      middlewares: ["auth-bob"]
    whoami-alice:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/alice\`)"
      middlewares: ["auth-alice"]
      service: whoami
`);

  await expectGotoOkay(page, 'http://localhost:9080/alice');
  const response = await login(
    page,
    'alice@example.com',
    'alice123',
    'http://localhost:9080/alice',
  );
  expect(response.status()).toBe(200);
  await expectGotoOkay(page, 'http://localhost:9080/alice');

  // Shared session cookie: alice is not in bob's AssertClaims → 403 when CheckOnEveryRequest.
  await expect
    .poll(async () => (await page.goto('http://localhost:9080/bob'))?.status(), {
      timeout: 10_000,
    })
    .toBe(403);
});

test('test UnauthorizedBehavior Challenge does not cause a redirect loop', async ({ page }) => {
  await configureTraefik(`
http:
${whoamiService()}

  middlewares:
    auth:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com", "alice@example.com"]
            CheckOnEveryRequest: true
`)}
    auth-bob:
      plugin:
${baseMiddleware(`
          UnauthenticatedBehavior: Auto
          UnauthorizedBehavior: Challenge
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["bob@example.com"]
            CheckOnEveryRequest: true
`)}
    auth-alice:
      plugin:
${baseMiddleware(`
          Authorization:
            AssertClaims:
              - Name: email
                AnyOf: ["alice@example.com"]
            CheckOnEveryRequest: true
`)}

  routers:
    oidc-callback:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/oidc/callback\`)"
      service: noop@internal
      middlewares: ["auth"]
    whoami-bob:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/bob\`)"
      service: whoami
      middlewares: ["auth-bob"]
    whoami-alice:
      entryPoints: ["web"]
      rule: "PathPrefix(\`/alice\`)"
      middlewares: ["auth-alice"]
      service: whoami
`);

  await expectGotoOkay(page, 'http://localhost:9080/alice');
  const response = await login(
    page,
    'alice@example.com',
    'alice123',
    'http://localhost:9080/alice',
  );
  expect(response.status()).toBe(200);
  await expectGotoOkay(page, 'http://localhost:9080/alice');

  // auth-bob Challenge: bounces alice through IdP once via shared permissive callback.
  // Without ChallengeAttempted this loops (ERR_TOO_MANY_REDIRECTS); with it → 403.
  // Mock IdP always shows the login form (no silent SSO), so complete one interactive challenge.
  await page.goto('http://localhost:9080/bob');
  await expect(page.locator('#username')).toBeVisible({ timeout: 10_000 });
  const challenged = await login(
    page,
    'alice@example.com',
    'alice123',
    /http:\/\/localhost:9080\/bob/,
    [403],
  );
  expect(challenged.status()).toBe(403);
});

async function login(
  page: Page,
  username: string,
  password: string,
  waitForUrl: string | RegExp,
  acceptedStatuses: number[] = [200],
): Promise<Response> {
  await page.locator('#username').waitFor({ state: 'visible' });
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);

  const allowed = new Set(acceptedStatuses);
  const responsePromise = page.waitForResponse((response) => {
    if (!allowed.has(response.status())) return false;
    if (typeof waitForUrl === 'string') {
      return response.url().startsWith(waitForUrl);
    }
    return waitForUrl.test(response.url());
  });

  await page.locator('#kc-login').click();
  return responsePromise;
}

async function expectGotoOkay(page: Page, url: string) {
  const response = await page.goto(url);
  expect(response?.status()).toBe(200);
}

async function loginAndGetToken(username: string): Promise<string> {
  const tokenResponse = await fetch(`${PROVIDER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username,
      password: 'ignored',
      client_id: 'traefik',
      client_secret: 'test-secret',
      scope: 'openid profile email',
    }),
  });

  expect(tokenResponse.ok).toBeTruthy();
  const tokens = await tokenResponse.json();
  expect(tokens.id_token).toBeTruthy();
  return tokens.id_token;
}
