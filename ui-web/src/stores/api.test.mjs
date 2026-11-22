/**
 * The three rules every request to the instance goes by.
 *
 * The console has no test runner, so this file is a plain Node test, run
 * through Vite's own SSR build — the only bundler the tree has, and the one
 * that already resolves this tree's extensionless imports. The CI job runs it
 * (`npm run test:stores`), which builds each of the store's test files and
 * runs it:
 *
 *   npx vite build --ssr src/stores/api.test.mjs --outDir dist-ssr --logLevel error
 *   node dist-ssr/api.test.js
 *
 * The rules are worth a test because none of them is the browser's job: the
 * token travels with every request, a write says it is a write, and a
 * failure carries the instance's own answer rather than a guess.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

/** Every request the console made, in order. */
const requests = [];

/** What the instance answers with. */
let answer = { status: 200, body: '{}' };

/** What the browser keeps between visits. */
const stored = new Map();

globalThis.localStorage = {
  getItem: (key) => (stored.has(key) ? stored.get(key) : null),
  setItem: (key, value) => void stored.set(key, value),
  removeItem: (key) => void stored.delete(key),
};

globalThis.fetch = async (path, init = {}) => {
  requests.push({
    path,
    method: init.method ?? 'GET',
    headers: new Headers(init.headers ?? {}),
  });
  return {
    ok: answer.status >= 200 && answer.status < 300,
    status: answer.status,
    text: async () => answer.body,
  };
};

const { apiGet, apiWrite, WRITE_HEADER } = await import('../api/client');
const { useTokenStore } = await import('./token');
const { addRoute, removeRoute } = await import('./routes');

/** A console with a token in it and nothing asked of the instance yet. */
function consoleWithToken(token = 'a-token') {
  stored.clear();
  requests.length = 0;
  answer = { status: 200, body: '{}' };
  useTokenStore().setToken(token);
  return useTokenStore();
}

test('a read carries the admin token', async () => {
  consoleWithToken('the-token');
  await apiGet('/api/status');

  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers.get('Authorization'), 'Bearer the-token');
});

test('a read does not claim to be a write', async () => {
  consoleWithToken();
  await apiGet('/api/status');

  assert.equal(requests[0].headers.get(WRITE_HEADER), null);
});

test('a write carries the token and says it is a write', async () => {
  consoleWithToken('the-token');
  await apiWrite('/api/clients', 'POST', { client_id: 'laptop' });

  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].headers.get('Authorization'), 'Bearer the-token');
  assert.equal(requests[0].headers.get(WRITE_HEADER), '1');
});

test('a write says what it wants in the body', async () => {
  consoleWithToken();
  await apiWrite('/api/clients', 'POST', { client_id: 'laptop' });

  assert.equal(requests[0].headers.get('Content-Type'), 'application/json');
});

test('a refusal carries the instance\'s own answer', async () => {
  consoleWithToken();
  answer = { status: 401, body: 'no token' };

  await assert.rejects(() => apiGet('/api/status'), (error) => {
    assert.equal(error.status, 401);
    assert.equal(error.unauthorized, true);
    assert.match(error.message, /no token/);
    return true;
  });
});

test('a token survives a reload', () => {
  consoleWithToken('kept');
  const { hasToken } = useTokenStore();

  assert.equal(hasToken(), true);
  assert.equal([...stored.values()].includes('kept'), true);
});

test('forgetting the token sends nothing', () => {
  consoleWithToken();
  useTokenStore().clearToken();

  assert.equal(useTokenStore().hasToken(), false);
  assert.equal(stored.size, 0);
});

test('a route the console adds asks the instance for it', async () => {
  consoleWithToken();
  answer = { status: 200, body: '{"routes":[]}' };

  await addRoute({
    host_pattern: 'console.example',
    path_pattern: '/api',
    backends: ['http://127.0.0.1:9090'],
  });

  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/api/routes');
  assert.equal(requests[0].headers.get(WRITE_HEADER), '1');
});

test('a route the console removes is named by the id the list gave it', async () => {
  consoleWithToken();
  answer = { status: 200, body: '{"routes":[]}' };

  await removeRoute(3);

  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'DELETE');
  assert.equal(requests[0].path, '/api/routes/3');
  assert.equal(requests[0].headers.get(WRITE_HEADER), '1');
});
