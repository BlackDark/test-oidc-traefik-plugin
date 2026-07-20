import * as fs from 'node:fs';
import * as path from 'node:path';

const ROUTERS_API = 'http://localhost:8080/api/http/routers';
const MIDDLEWARES_API = 'http://localhost:8080/api/http/middlewares';

type TraefikRouter = { name?: string; provider?: string };
type TraefikMiddleware = {
  name?: string;
  provider?: string;
  plugin?: { 'traefik-oidc-auth'?: { CookieNamePrefix?: string } };
};

function routerNamesFromYaml(yaml: string): string[] {
  const match = yaml.match(/(?:^|\n) {2}routers:\n([\s\S]*?)(?=\n {2}\w|\n*$)/);
  if (!match) return [];
  return [...match[1].matchAll(/^ {4}([\w-]+):/gm)].map((m) => m[1]);
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function fileRouterNames(): Promise<string[] | null> {
  const routers = await fetchJson<TraefikRouter[]>(ROUTERS_API);
  if (!Array.isArray(routers)) return null;
  return routers
    .filter((r) => r.provider === 'file' && typeof r.name === 'string')
    .map((r) => r.name!.replace(/@file$/, ''));
}

async function fileOidcPrefixes(): Promise<string[] | null> {
  const middlewares = await fetchJson<TraefikMiddleware[]>(MIDDLEWARES_API);
  if (!Array.isArray(middlewares)) return null;
  return middlewares
    .filter((m) => m.provider === 'file' && m.plugin?.['traefik-oidc-auth'])
    .map((m) => m.plugin?.['traefik-oidc-auth']?.CookieNamePrefix ?? '');
}

export async function configureTraefik(yaml: string) {
  const filePath = path.join(__dirname, '.http.yml');
  const marker = `e2e${Date.now()}`;
  const stamped = yaml.replace(
    /traefik-oidc-auth:/g,
    `traefik-oidc-auth:\n          CookieNamePrefix: "${marker}"`,
  );
  const expectedRouters = routerNamesFromYaml(stamped).sort();
  fs.writeFileSync(filePath, stamped);

  // beforeAll writes config before Traefik is up — nothing to wait on.
  if ((await fileRouterNames()) === null) {
    return;
  }

  const deadline = Date.now() + 20_000;
  let last = '';
  while (Date.now() < deadline) {
    const routers = ((await fileRouterNames()) ?? []).sort();
    const prefixes = (await fileOidcPrefixes()) ?? [];
    last = `routers=[${routers.join(',')}] prefixes=[${prefixes.join(',')}]`;

    const routersReady =
      expectedRouters.length > 0 &&
      routers.length === expectedRouters.length &&
      expectedRouters.every((name, i) => name === routers[i]);

    const middlewaresReady =
      prefixes.length > 0 && prefixes.every((prefix) => prefix === marker);

    if (routersReady && middlewaresReady) {
      await new Promise((r) => setTimeout(r, 200));
      return;
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  throw new Error(`Traefik config not ready. ${last}`);
}
