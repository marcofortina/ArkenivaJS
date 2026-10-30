// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type {} from '@fastify/csrf-protection';
import { fixtureSettings, startFixture } from './fixture.js';
import { securityHttpPlugin } from '../../dist/index.js';
import { headerPolicy } from '../../dist/headers.js';
import { capture } from '../../dist/settings.js';

const policyFailure = { code: 'EK_HTTP_SECURITY_POLICY' };
const csrfFailure = { code: 'EK_HTTP_CSRF' };

test('HTTP header policy rejects missing defaults, invalid directives and unbounded or contradictory frame sources', () => {
  const f = fixtureSettings(),
    base = f.settings.policy;
  try {
    for (const patch of [
      { csrfEnabled: 'true' },
      { contentSecurityPolicy: { 'object-src': ["'none'"] } },
      { contentSecurityPolicy: { 'default-src': [] } },
      { contentSecurityPolicy: { 'default-src': ["'self'"], Bad: ["'self'"] } },
      { contentSecurityPolicy: { 'default-src': ["'self'"], 'frame-ancestors': ["'none'"] } },
      { contentSecurityPolicy: { 'default-src': ['https://é.example'] } },
      { contentSecurityPolicy: { 'default-src': Array(17).fill('a'.repeat(512)) } },
      { frameAncestors: [] },
      { frameAncestors: ["'none'", "'self'"] },
      ...[
        'http://frame.fixture.invalid',
        'https://frame.fixture.invalid/path',
        'https://user:password@frame.fixture.invalid',
      ].map((value) => ({ frameAncestors: [value] })),
    ])
      assert.throws(() => headerPolicy({ ...base, ...patch }), policyFailure);
    const allowed = headerPolicy({
      ...base,
      frameAncestors: ["'self'", 'https://frame.fixture.invalid'],
    });
    assert.deepEqual(allowed.frameAncestors, ["'self'", 'https://frame.fixture.invalid']);
  } finally {
    f.keys.current.fill(0);
  }
});

test('HTTP settings reject duplicate routes and origins, invalid paths and executable provider classifications', () => {
  const f = fixtureSettings();
  let effects = 0;
  try {
    for (const patch of [
      { allowedOrigins: [f.settings.allowedOrigins![0], f.settings.allowedOrigins![0]] },
      { cookieRoutes: [f.settings.cookieRoutes![0], f.settings.cookieRoutes![0]] },
      ...['relative', '/unsafe?x', '/unsafe/*', '/unsafe/../path'].map((path) => ({
        cookieRoutes: [{ method: 'POST', path }],
      })),
      ...['127.0.0.1/33', '::1/129', 'bad/8', '127.0.0.1/-1'].map((cidr) => ({
        trustedProxyCidrs: [cidr],
      })),
      { authority: { ...f.settings.authority, usage: 'unsupported' } },
      {
        authority: Object.defineProperty({}, 'usage', {
          get() {
            effects++;
            throw new Error('Classification metadata must not execute');
          },
        }),
      },
    ])
      assert.throws(() => securityHttpPlugin({ ...f.settings, ...patch } as never), policyFailure);
    assert.equal(effects, 0);
    assert.equal(
      capture({ ...f.settings, trustedProxyCidrs: ['127.0.0.0/8', '::1/128'] }).permitsProxy(
        'not-an-ip',
      ),
      false,
    );
  } finally {
    f.keys.current.fill(0);
  }
});

test('HTTP data, array, origin and method ingress reject executable descriptors and invalid authority data', async () => {
  const { fields, array, origin, method } = await import('../../dist/validation.js');
  let effects = 0;
  const accessor = Object.defineProperty(new Array(1), '0', {
    get() {
      effects++;
      throw new Error('Array accessors must not execute');
    },
  });
  for (const value of [new Array(1), accessor]) assert.throws(() => array(value, 2), policyFailure);
  for (const value of [
    Object.fromEntries(Array.from({ length: 65 }, (_, index) => ['key' + index, true])),
    { [Symbol('unexpected')]: true },
  ])
    assert.throws(() => fields(value), policyFailure);
  for (const value of [
    'http://foreign.fixture.invalid',
    'https://user:password@fixture.invalid',
    'https://*.fixture.invalid',
    'not-a-url',
  ])
    assert.throws(() => origin(value), policyFailure);
  for (const value of [
    null,
    {},
    { run: false },
    Object.defineProperty({}, 'run', {
      get() {
        effects++;
        throw new Error('Method accessors must not execute');
      },
    }),
  ])
    assert.throws(() => method(value, 'run'), policyFailure);
  assert.equal(effects, 0);
});

test('HTTP native-key admission aborts before its scheduled callback without accessing secrets', async () => {
  const { providerTask } = await import('../../dist/provider-task.js');
  const f = fixtureSettings(),
    owner = new AbortController();
  let calls = 0;
  const digest = f.settings.csrfHmac.digest;
  f.settings.csrfHmac.digest = async (...args) => {
    calls++;
    return Reflect.apply(digest, f.settings.csrfHmac, args);
  };
  const task = providerTask(capture(f.settings), owner.signal);
  try {
    const pending = task.load();
    owner.abort();
    await assert.rejects(pending, { code: 'EK_ABORTED' });
    assert.equal(calls, 0);
  } finally {
    await task.close();
    f.keys.current.fill(0);
  }
});

test('HTTP durable CSRF records reject corrupted binding, owner, expiry and executable row fields', async () => {
  const f = await startFixture();
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    const context = { sessionId: f.alice.sessionId, origin: 'https://app.fixture.invalid' };
    const entry = [...f.rows.entries()][0]!;
    for (const patch of [
      { kind: 'wrong-state' },
      { binding: 'foreign' },
      { ownerKey: 'foreign' },
      { expiresAt: 'invalid' },
      { expiresAt: new Date(Date.now() + 3600000).toISOString() },
    ]) {
      f.rows.set(entry[0], { ...entry[1], ...patch });
      await assert.rejects(
        f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token)),
        csrfFailure,
      );
      f.rows.set(entry[0], entry[1]);
      await f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token));
    }
    f.rows.set(entry[0], { ...entry[1], extra: true });
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token)),
      csrfFailure,
    );
    f.rows.set(entry[0], entry[1]);
    assert.equal(f.state.effects, 0);
  } finally {
    await f.close();
    f.keys.current.fill(0);
  }
});

test('Native HTTP refuses malformed existing CSRF cookies and permits only the exact Referer fallback', async () => {
  const f = await startFixture();
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    for (const nonce of ['invalid', randomBytes(32).toString('base64url').slice(0, -1) + '_']) {
      const response = await fetch(f.origin + '/token', {
        headers: {
          cookie: '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + nonce,
          'x-session-hint': f.alice.sessionId,
        },
      });
      assert.equal(response.status, 403);
      await response.arrayBuffer();
    }
    const base = {
      cookie: '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1],
      'x-csrf-token': token,
    };
    for (const referer of [
      'https://app.fixture.invalid/#fragment',
      'https://app.fixture.invalid/' + 'x'.repeat(2048),
    ]) {
      const response = await fetch(f.origin + '/protected', {
        method: 'POST',
        headers: { ...base, referer },
      });
      assert.equal(response.status, 403);
      await response.arrayBuffer();
    }
    assert.equal(f.state.effects, 0);
  } finally {
    await f.close();
    f.keys.current.fill(0);
  }
});

test('HTTP operation ownership enforces readiness, deadlines and hostile provider failure privacy', async () => {
  const { runtime } = await import('../../dist/runtime.js');
  const f = fixtureSettings(),
    controller = new AbortController();
  let ready = false;
  const owner = runtime(
    capture(f.settings),
    controller.signal,
    () => ready,
    () => undefined,
  );
  try {
    await assert.rejects(
      owner.run(undefined, async () => {}),
      { code: 'EK_LIFECYCLE_STATE' },
    );
    ready = true;
    await assert.rejects(
      owner.run({ timeoutMs: 5 }, async (call) => {
        const end = performance.now() + 10;
        while (performance.now() < end) {
          /* Keep the actual event loop until the monotonic deadline passes. */
        }
        call.check();
      }),
      { code: 'EK_TIMEOUT' },
    );
    await assert.rejects(
      owner.run(undefined, async () => {
        throw new Proxy(
          {},
          {
            getPrototypeOf() {
              throw new Error('Private provider exception metadata');
            },
          },
        );
      }),
      csrfFailure,
    );
    await assert.rejects(
      owner.run(undefined, async () => {
        throw new Error('Private provider failure');
      }),
      csrfFailure,
    );
  } finally {
    await owner.close();
    f.keys.current.fill(0);
  }
});

test('HTTP optional catalogs retain bearer-only defaults and reject excessive classification depth', () => {
  const f = fixtureSettings();
  try {
    const { allowedOrigins, cookieRoutes, cookieSession, ...withoutCatalogs } = f.settings;
    assert.ok(allowedOrigins && cookieRoutes && cookieSession);
    assert.doesNotThrow(() =>
      securityHttpPlugin({
        ...withoutCatalogs,
        policy: { ...f.settings.policy, csrfEnabled: false },
      }),
    );
    let prototype: object = {};
    for (let index = 0; index < 65; index++) prototype = Object.create(prototype);
    const authority = Object.assign(Object.create(prototype), f.settings.authority);
    assert.throws(() => securityHttpPlugin({ ...f.settings, authority }), policyFailure);
  } finally {
    f.keys.current.fill(0);
  }
});

test('Native HTTP rejects a configured cookie route that has no installed handler', async () => {
  const f = fixtureSettings();
  f.settings = {
    ...f.settings,
    cookieRoutes: [{ method: 'POST', path: '/missing-cookie-handler' }],
  };
  try {
    await assert.rejects(startFixture(f));
  } finally {
    f.keys.current.fill(0);
  }
});

test('Native HTTP CSRF adapter exceptions fail closed after actual verification and never invoke a protected handler', async () => {
  const f = await startFixture();
  const { COMPONENTS } = await import('@arkenivajs/core');
  const server = f.app.resolve<import('@arkenivajs/api').ManagedApiServer>(COMPONENTS.api).native();
  const original = server.csrfProtection;
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    const headers = {
      cookie: '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1],
      'x-csrf-token': token,
      origin: 'https://app.fixture.invalid',
    };
    const accepted = await fetch(f.origin + '/protected', { method: 'POST', headers });
    assert.equal(accepted.status, 200);
    await accepted.arrayBuffer();
    Object.defineProperty(server, 'csrfProtection', {
      configurable: true,
      value() {
        throw new Error('Private native middleware failure');
      },
    });
    const denied = await fetch(f.origin + '/protected', { method: 'POST', headers });
    assert.equal(denied.status, 403);
    await denied.arrayBuffer();
    assert.equal(f.state.effects, 1);
    Object.defineProperty(server, 'csrfProtection', { value: original });
    const recovered = await fetch(f.origin + '/protected', { method: 'POST', headers });
    assert.equal(recovered.status, 200);
    await recovered.arrayBuffer();
    assert.equal(f.state.effects, 2);
  } finally {
    Object.defineProperty(server, 'csrfProtection', { value: original });
    await f.close();
    f.keys.current.fill(0);
  }
});

test('HTTP initial native key errors and hostile exceptions remain private and cannot initialize a service', async () => {
  for (const value of ['', 'short', '\u0080'.repeat(32)]) {
    const f = fixtureSettings();
    f.settings.csrfHmac.digest = async () => value;
    try {
      await assert.rejects(startFixture(f));
    } finally {
      f.keys.current.fill(0);
    }
  }
  const f = fixtureSettings();
  f.settings.csrfHmac.digest = async () => {
    throw new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('Private native key exception metadata');
        },
      },
    );
  };
  try {
    await assert.rejects(startFixture(f));
  } finally {
    f.keys.current.fill(0);
  }
});

test('HTTP service rejects malformed runtime policy updates and invalid authorized subjects without issuing state', async () => {
  const input = fixtureSettings(),
    require = input.settings.authority.require;
  let invalid = true;
  input.settings.authority.require = async (...args) => {
    const subject = await Reflect.apply(require, input.settings.authority, args);
    return invalid ? { ...subject, issuer: '' } : subject;
  };
  const f = await startFixture(input);
  try {
    assert.throws(
      () => f.service.installHeaders({ ...f.settings.policy, hstsMaxAgeSeconds: 0 }),
      policyFailure,
    );
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
      policyFailure,
    );
    assert.equal(f.rows.size, 0);
    invalid = false;
    assert.ok(
      (
        await f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId }))
      ).startsWith('v1.'),
    );
  } finally {
    await f.close();
    f.keys.current.fill(0);
  }
});

test('HTTP valid unrecognized browser nonces renew through actual persistent state rather than trusting a cookie', async () => {
  const f = await startFixture();
  try {
    const nonce = randomBytes(32).toString('base64url');
    const response = await fetch(f.origin + '/token', {
      headers: {
        cookie: '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + nonce,
        'x-session-hint': f.alice.sessionId,
      },
    });
    assert.equal(response.status, 200);
    const body = (await response.json()) as { token: string };
    assert.notEqual(body.token.split('.')[1], nonce);
    assert.equal(f.rows.size, 1);
    assert.equal(f.state.effects, 0);
  } finally {
    await f.close();
    f.keys.current.fill(0);
  }
});

test('Native HTTP rejects late security registration and preserves the already-owned listener', async () => {
  const { createApi } = await import('@arkenivajs/api');
  const { createNative } = await import('../../dist/native.js');
  const { providerTask } = await import('../../dist/provider-task.js');
  const f = fixtureSettings(),
    owner = new AbortController(),
    settings = capture({ ...f.settings, cookieRoutes: [] });
  const key = providerTask(settings, owner.signal);
  const api = createApi({
    service: { name: 'late-http-security', version: '1.0.0', environment: 'test' },
    host: '127.0.0.1',
    port: 0,
  });
  api.get('/ready', {
    schema: {
      response: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] },
    },
    auth: { required: false },
    handler: () => ({ ok: true }),
  });
  try {
    await api.start();
    await assert.rejects(
      createNative(settings, api.native(), owner.signal, () => true, true, key),
      policyFailure,
    );
    const response = await fetch(api.address()! + '/ready');
    assert.equal(response.status, 200);
    await response.arrayBuffer();
  } finally {
    owner.abort();
    await key.close();
    await api.close();
    f.keys.current.fill(0);
  }
});

test('Native protected cookie routes reject plaintext before resolving identity even on real loopback traffic', async () => {
  const { createApi } = await import('@arkenivajs/api');
  const { createNative } = await import('../../dist/native.js');
  const { providerTask } = await import('../../dist/provider-task.js');
  const f = fixtureSettings(),
    owner = new AbortController(),
    settings = capture(f.settings);
  const key = providerTask(settings, owner.signal);
  const api = createApi({
    service: { name: 'insecure-cookie-route', version: '1.0.0', environment: 'test' },
    host: '127.0.0.1',
    port: 0,
  });
  let ready = false,
    effects = 0;
  const managed = await createNative(settings, api.native(), owner.signal, () => ready, false, key);
  api.post('/protected', {
    schema: {
      response: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] },
    },
    auth: { required: false },
    handler: () => {
      effects++;
      return { ok: true };
    },
  });
  try {
    await api.start();
    ready = true;
    const response = await fetch(api.address()! + '/protected', {
      method: 'POST',
      headers: {
        cookie: '__Host-session=' + f.alice.cookie,
        origin: 'https://app.fixture.invalid',
      },
    });
    assert.equal(response.status, 403);
    await response.arrayBuffer();
    assert.equal(effects, 0);
    assert.equal(f.state.authorizations, 0);
  } finally {
    ready = false;
    await managed.close();
    owner.abort();
    await key.close();
    await api.close();
    f.keys.current.fill(0);
  }
});

test('HTTP security initialization rejects an unprepared context before acquiring capabilities', async () => {
  const f = fixtureSettings();
  try {
    const plugin = securityHttpPlugin(f.settings);
    await assert.rejects(
      async () => plugin.init({ options: { service: { environment: 'test' } } } as never),
      policyFailure,
    );
    assert.equal(f.state.authorizations, 0);
    assert.equal(f.state.writes, 0);
  } finally {
    f.keys.current.fill(0);
  }
});

test('HTTP security capability publication failure rolls back the actual native owner', async () => {
  const { createApplication } = await import('@arkenivajs/core');
  const { apiPlugin } = await import('@arkenivajs/api');
  const { loggingPlugin } = await import('@arkenivajs/logging');
  const f = fixtureSettings(),
    plugin = securityHttpPlugin(f.settings),
    initialize = plugin.init;
  const app = await createApplication({
    service: { name: 'http-security-publication-failure', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [
      loggingPlugin(),
      apiPlugin(),
      {
        ...plugin,
        async init(context) {
          const intercepted = new Proxy(context, {
            get(target, key) {
              if (key === 'provide')
                return () => {
                  throw new Error('Private capability publication failure');
                };
              return Reflect.get(target, key, target);
            },
          });
          await Reflect.apply(initialize, plugin, [intercepted]);
        },
      },
    ],
  });
  try {
    await assert.rejects(app.start());
    assert.equal(f.state.writes, 0);
    assert.equal(f.state.authorizations, 0);
  } finally {
    await app.stop();
    f.keys.current.fill(0);
  }
});

test('Native client disconnect aborts the live provider signal before its independent deadline', async () => {
  const { request } = await import('node:http');
  const { within } = await import('@arkenivajs/core/support');
  const { setTimeout: pause } = await import('node:timers/promises');
  const input = fixtureSettings();
  input.settings = {
    ...input.settings,
    csrfStore: { ...input.settings.csrfStore, operationTimeoutMs: 5000 },
  };
  const read = input.settings.csrfStore.store.read;
  let armed = false,
    signal: AbortSignal | undefined,
    entered: () => void = () => {},
    release: () => void = () => {};
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  input.settings.csrfStore.store.read = async (...args) => {
    if (armed) {
      signal = args[2]?.signal;
      entered();
      await held;
    }
    return Reflect.apply(read, input.settings.csrfStore.store, args);
  };
  const f = await startFixture(input);
  let outgoing: ReturnType<typeof request> | undefined;
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    armed = true;
    outgoing = request(f.origin + '/protected', {
      method: 'POST',
      headers: {
        cookie:
          '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1],
        origin: 'https://app.fixture.invalid',
        'x-csrf-token': token,
      },
    });
    outgoing.on('error', () => undefined);
    outgoing.end();
    await within(() => started, { timeoutMs: 1000 });
    assert.ok(signal);
    assert.equal(signal.aborted, false);
    outgoing.destroy();
    const deadline = performance.now() + 1000;
    while (!signal.aborted) {
      assert.ok(
        performance.now() < deadline,
        'Client disconnect did not abort the native request owner',
      );
      await pause(5);
    }
    release();
    assert.equal(f.state.effects, 0);
  } finally {
    outgoing?.destroy();
    release();
    await f.close();
    f.keys.current.fill(0);
  }
});
