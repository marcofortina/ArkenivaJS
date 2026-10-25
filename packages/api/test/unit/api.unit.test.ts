// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { get as rawGet, createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError, COMPONENTS } from '@arkenivajs/core';
import type { Application, ErrorCode, RouteContext } from '@arkenivajs/core';
import { createApi, apiPlugin } from '@arkenivajs/api';
import { httpPlugin } from '@arkenivajs/http';
import type { ManagedApiServer } from '@arkenivajs/api';
import type { ApiObservation } from '@arkenivajs/api';

const service = { name: 'api-test', version: '1.0.0', environment: 'test' as const };
const schema = {
  type: 'object',
  required: ['value'],
  additionalProperties: false,
  properties: { value: { type: 'string' } },
};
const publicRoute = (handler: () => unknown) => ({
  schema: { response: schema },
  auth: { required: false },
  handler,
});
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;

test('EK-HTTP-001 five verbs validate request/response without coercion and expose sorted OpenAPI', async () => {
  const events: ApiObservation[] = [];
  const api = createApi({
    service,
    port: 0,
    onObservation(event) {
      assert.ok(Object.isFrozen(event));
      events.push(event);
    },
  });
  api.get(
    '/z',
    publicRoute(() => ({ value: 'z' })),
  );
  for (const method of ['get', 'post', 'put', 'patch', 'delete'] as const)
    api[method]<{ name: string }, Record<string, never>, { value: string }, { value: string }>(
      '/hello/:name',
      {
        schema: {
          params: {
            type: 'object',
            properties: { name: { type: 'string', minLength: 1 } },
            required: ['name'],
            additionalProperties: false,
          },
          ...(method === 'get' ? {} : { body: schema }),
          response: schema,
        },
        auth: { required: false },
        handler: (context) => {
          assert.ok(Object.isFrozen(context));
          return { value: context.params.name };
        },
      },
    );
  assert.equal(api.address(), undefined);
  assert.throws(() => api.openApiDocument(), code('EK_LIFECYCLE_STATE'));
  try {
    await api.start();
    await api.start();
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
      const response = await fetch(api.address() + '/hello/Ada', {
        method,
        ...(method === 'GET'
          ? {}
          : { headers: { 'content-type': 'application/json' }, body: '{"value":"body"}' }),
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { value: 'Ada' });
    }
    const invalid = await api
      .native()
      .inject({ method: 'POST', url: '/hello/Ada', payload: { value: 1 } });
    assert.equal(invalid.statusCode, 400);
    assert.equal(invalid.json().error.code, 'EK_HTTP_VALIDATION');
    const document = api.openApiDocument();
    assert.ok(Object.isFrozen(document));
    assert.equal(document.openapi, '3.1.0');
    assert.deepEqual(Object.keys(document.paths as object), ['/hello/{name}', '/z']);
    assert.ok(events.some((event) => event.route === '/hello/:name' && event.responseBytes! > 0));
    assert.ok(events.every((event) => event.durationMs >= 0));
    assert.equal(api.stats().active, 0);
    assert.throws(
      () =>
        api.get(
          '/later',
          publicRoute(() => ({})),
        ),
      code('EK_LIFECYCLE_STATE'),
    );
    assert.throws(
      () => api.registerMiddleware('preHandler', async (_ctx, next) => next()),
      code('EK_LIFECYCLE_STATE'),
    );
  } finally {
    await api.close();
  }
  await api.close();
  await assert.rejects(api.start(), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => api.native(), code('EK_RESOURCE_CLOSED'));
});

test('EK-HTTP-001 typed failures use stable HTTP mappings and never disclose native details', async () => {
  const api = createApi({ service, port: 0 });
  const failures: [ErrorCode, number][] = [
    ['EK_HTTP_VALIDATION', 400],
    ['EK_AUTH_REQUIRED', 401],
    ['EK_AUTH_INVALID', 401],
    ['EK_AUTH_FORBIDDEN', 403],
    ['EK_TENANT_UNVERIFIED', 403],
    ['EK_MFA_POLICY', 500],
    ['EK_MFA_ASSURANCE_REQUIRED', 403],
    ['EK_MFA_INVALID', 401],
    ['EK_MFA_EXPIRED', 410],
    ['EK_MFA_REPLAY', 409],
    ['EK_MFA_RATE_LIMIT', 429],
    ['EK_MFA_STORAGE', 503],
    ['EK_MFA_ALREADY_ENROLLED', 409],
    ['EK_MFA_ENROLLMENT_EXPIRED', 410],
    ['EK_MFA_CHALLENGE_EXPIRED', 410],
    ['EK_MFA_CREDENTIAL_CONFLICT', 409],
    ['EK_MFA_COUNTER_REGRESSION', 409],
    ['EK_HTTP_NOT_FOUND', 404],
    ['EK_HTTP_RATE_LIMIT', 429],
    ['EK_TIMEOUT', 408],
    ['EK_BACKEND_UNAVAILABLE', 503],
    ['EK_INTERNAL', 500],
  ];
  for (const [failure] of failures)
    api.get(
      '/' + failure,
      publicRoute(() => {
        throw new KitError({
          code: failure,
          message: 'fake-private-message',
          cause: new Error('fake-secret-cause'),
        });
      }),
    );
  api.get(
    '/upstream',
    publicRoute(() => {
      throw new KitError({ code: 'EK_TIMEOUT', message: 'private', details: { upstream: true } });
    }),
  );
  api.get(
    '/native',
    publicRoute(() => {
      throw new Error('fake-private-stack');
    }),
  );
  api.get(
    '/invalid-response',
    publicRoute(() => ({ value: 1, password: 'fake-private-response' })),
  );
  try {
    await api.start();
    for (const [failure, status] of failures) {
      const response = await api.native().inject('/' + failure);
      assert.equal(response.statusCode, status);
      assert.equal(response.json().error.code, failure);
      assert.ok(response.json().error.requestId);
      assert.ok(!response.body.includes('fake-'));
    }
    assert.equal((await api.native().inject('/upstream')).statusCode, 504);
    for (const path of ['/native', '/invalid-response']) {
      const response = await api.native().inject(path);
      assert.equal(response.statusCode, 500);
      assert.ok(!response.body.includes('fake-'));
    }
    assert.equal((await api.native().inject('/missing')).json().error.code, 'EK_HTTP_NOT_FOUND');
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 middleware order is FIFO and cannot short-circuit silently or call next twice', async () => {
  const events: string[] = [];
  let handled = 0;
  const api = createApi({ service, port: 0 });
  api.registerMiddleware('postAuthentication', async (_ctx, next) => {
    events.push('auth');
    await next();
  });
  api.registerMiddleware('preHandler', async (ctx, next) => {
    events.push('first');
    if (ctx.headers['x-mode'] === 'stop') return;
    if (ctx.headers['x-mode'] === 'deny')
      throw new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'denied' });
    await next();
    if (ctx.headers['x-mode'] === 'twice') await next();
  });
  api.registerMiddleware('preHandler', async (_ctx, next) => {
    events.push('second');
    await next();
  });
  api.get(
    '/',
    publicRoute(() => {
      handled++;
      return { value: 'ok' };
    }),
  );
  try {
    await api.start();
    assert.equal((await api.native().inject('/')).statusCode, 200);
    assert.deepEqual(events, ['auth', 'first', 'second']);
    assert.equal(
      (await api.native().inject({ url: '/', headers: { 'x-mode': 'stop' } })).statusCode,
      500,
    );
    assert.equal(
      (await api.native().inject({ url: '/', headers: { 'x-mode': 'deny' } })).statusCode,
      403,
    );
    assert.equal(
      (await api.native().inject({ url: '/', headers: { 'x-mode': 'twice' } })).statusCode,
      500,
    );
    assert.equal(handled, 2);
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 protected routes reject absent providers; public routes never receive trusted context', async () => {
  const absent = createApi({ service, port: 0 });
  absent.get('/', { ...publicRoute(() => ({ value: 'ok' })), auth: { required: true } });
  await assert.rejects(absent.start(), code('EK_PLUGIN_DEPENDENCY'));
  await absent.close();
  let verified = 0,
    scopes = 0;
  const auth: NonNullable<Application['auth']> = {
    async verifyBearer(header) {
      verified++;
      if (!header) throw new KitError({ code: 'EK_AUTH_REQUIRED', message: 'missing' });
      return {
        subject: 'example',
        issuer: 'https://issuer.invalid',
        audience: ['api'],
        scopes: ['read'],
        claims: {},
      };
    },
    requireScope(_identity, scope) {
      assert.equal(scope, 'read');
      scopes++;
    },
    requireAssurance() {
      throw new KitError({ code: 'EK_MFA_ASSURANCE_REQUIRED', message: 'No assurance policy' });
    },
    tenantFrom(identity) {
      return {
        tenantId: 'trusted-tenant' as never,
        identity,
        verifiedAt: new Date().toISOString(),
        source: 'oidc',
      };
    },
  };
  const api = createApi({ service, port: 0, auth });
  api.get('/private', {
    schema: { response: schema },
    auth: { required: true, scopes: ['read'] },
    handler: (ctx: RouteContext) => ({ value: ctx.auth!.tenantId }),
  });
  api.get('/public', {
    ...publicRoute(() => ({ value: 'public' })),
    handler: (ctx: RouteContext) => {
      assert.equal(ctx.auth, undefined);
      return { value: 'public' };
    },
  });
  try {
    await api.start();
    assert.equal((await api.native().inject('/private')).statusCode, 401);
    const response = await api.native().inject({
      url: '/private',
      headers: { authorization: 'Bearer fake-test-token', 'x-tenant-id': 'forged' },
    });
    assert.equal(response.json().value, 'trusted-tenant');
    assert.equal(scopes, 1);
    await api
      .native()
      .inject({ url: '/public', headers: { authorization: 'Bearer fake-test-token' } });
    assert.equal(verified, 2);
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 handler deadline aborts context and body parser enforces the byte budget', async () => {
  let aborted = false;
  const api = createApi({ service, port: 0, requestTimeoutMs: 15, bodyLimitBytes: 32 });
  api.get('/slow', {
    schema: { response: schema },
    auth: { required: false },
    handler: (ctx: RouteContext) =>
      new Promise(() =>
        ctx.signal.addEventListener(
          'abort',
          () => {
            aborted = true;
          },
          { once: true },
        ),
      ),
  });
  api.post('/body', {
    schema: { body: schema, response: schema },
    auth: { required: false },
    handler: () => ({ value: 'ok' }),
  });
  try {
    await api.start();
    assert.equal((await api.native().inject('/slow')).statusCode, 408);
    assert.equal(aborted, true);
    assert.equal(
      (
        await api
          .native()
          .inject({ method: 'POST', url: '/body', payload: { value: 'x'.repeat(100) } })
      ).statusCode,
      400,
    );
    assert.equal(
      (
        await api.native().inject({
          method: 'POST',
          url: '/body',
          headers: { 'content-type': 'application/json' },
          payload: '{bad',
        })
      ).statusCode,
      400,
    );
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 client disconnect aborts handler and releases active bookkeeping', async () => {
  let entered!: () => void, cancelled!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const ended = new Promise<void>((resolve) => {
    cancelled = resolve;
  });
  const api = createApi({ service, port: 0 });
  api.get('/', {
    schema: { response: schema },
    auth: { required: false },
    handler: (ctx: RouteContext) => {
      entered();
      return new Promise(() => ctx.signal.addEventListener('abort', cancelled, { once: true }));
    },
  });
  try {
    await api.start();
    const req = rawGet(api.address()!);
    req.on('error', () => {});
    await ready;
    req.destroy();
    await ended;
    assert.equal(api.stats().active, 0);
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 graceful close drains completed work and bounds uncooperative handlers', async () => {
  const api = createApi({ service, port: 0 });
  let entered!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  api.get('/', {
    schema: { response: schema },
    auth: { required: false },
    handler: async () => {
      entered();
      await delay(20);
      return { value: 'ok' };
    },
  });
  await api.start();
  const response = fetch(api.address()!);
  await ready;
  await api.close();
  assert.deepEqual(await (await response).json(), { value: 'ok' });
  const hung = createApi({ service, port: 0 });
  let began!: () => void;
  const running = new Promise<void>((resolve) => {
    began = resolve;
  });
  hung.get('/', {
    schema: { response: schema },
    auth: { required: false },
    handler: () => {
      began();
      return new Promise(() => {});
    },
  });
  await hung.start();
  const failed = assert.rejects(fetch(hung.address()!));
  await running;
  await assert.rejects(hung.close({ timeoutMs: 10 }), code('EK_TIMEOUT'));
  await failed;
});

test('EK-HTTP-001 transport readiness, observer failures, duplicate registration and invalid policy are explicit', async () => {
  for (const options of [
    { port: -1 },
    { port: 65536 },
    { requestTimeoutMs: 0 },
    { bodyLimitBytes: 0 },
    { validateResponses: 'yes' },
  ])
    assert.throws(() => createApi({ service, ...options } as never), code('EK_CONFIG_INVALID'));
  const api = createApi({
    service,
    port: 0,
    isReady: () => false,
    onObservation() {
      throw new Error('fake-observer');
    },
  });
  assert.throws(
    () =>
      api.get(
        '/livez',
        publicRoute(() => ({})),
      ),
    code('EK_CONFIG_INVALID'),
  );
  assert.throws(
    () => api.get('/bad', { ...publicRoute(() => ({})), auth: undefined } as never),
    code('EK_CONFIG_INVALID'),
  );
  assert.throws(
    () => api.get('/bad', { ...publicRoute(() => ({})), schema: { response: true } } as never),
    code('EK_CONFIG_INVALID'),
  );
  api.get(
    '/x/:name',
    publicRoute(() => ({ value: 'ok' })),
  );
  assert.throws(
    () =>
      api.get(
        '/x/:other',
        publicRoute(() => ({})),
      ),
    code('EK_CONFIG_INVALID'),
  );
  assert.throws(
    () => api.registerMiddleware('unsafe' as never, async () => {}),
    code('EK_CONFIG_INVALID'),
  );
  try {
    await api.start();
    assert.equal((await api.native().inject('/livez')).statusCode, 200);
    assert.equal((await api.native().inject('/readyz')).statusCode, 503);
    assert.equal((await api.native().inject('/x/Ada')).statusCode, 503);
    assert.equal(api.stats().observerFailures, 3);
  } finally {
    await api.close();
  }
});

test('EK-HTTP-001 application facade registers before start and binds only after dependency initialization', async () => {
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const address = reserve.address();
  assert.ok(address && typeof address === 'object');
  const port = address.port;
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  const logger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
      return this;
    },
    setLevel() {},
    async flush() {},
  };
  const app = await createApplication({
    service,
    http: { host: '127.0.0.1', port },
    plugins: [
      {
        id: 'logging',
        version: '1.0.0',
        capabilities: new Set(['logger']),
        init(ctx) {
          ctx.provide(COMPONENTS.logger, logger);
        },
        close() {},
      },
      apiPlugin(),
    ],
  });
  app.api.get(
    '/',
    publicRoute(() => ({ value: 'ready' })),
  );
  try {
    await app.start();
    assert.equal((await fetch(`http://127.0.0.1:${port}/readyz`)).status, 200);
    assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/`)).json(), { value: 'ready' });
  } finally {
    await app.stop();
  }
});

test('EK-HTTP-001 application drain keeps downstream clients available to active handlers', async () => {
  const backend = createServer((_request, response) => response.end('{"value":"backend"}'));
  await new Promise<void>((resolve) => backend.listen(0, '127.0.0.1', resolve));
  const remote = backend.address();
  assert.ok(remote && typeof remote === 'object');
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const local = reserve.address();
  assert.ok(local && typeof local === 'object');
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  let entered!: () => void, released!: () => void, draining!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    released = resolve;
  });
  const drain = new Promise<void>((resolve) => {
    draining = resolve;
  });
  const logger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
      return this;
    },
    setLevel() {},
    async flush() {},
  };
  const origin = `http://127.0.0.1:${remote.port}`;
  const app = await createApplication({
    service,
    http: { host: '127.0.0.1', port: local.port },
    plugins: [
      {
        id: 'logging',
        version: '1.0.0',
        capabilities: new Set(['logger']),
        init(context) {
          context.provide(COMPONENTS.logger, logger);
        },
        close() {},
      },
      apiPlugin(),
      httpPlugin({ allowedOrigins: [origin], allowPrivateNetwork: true }),
    ],
  });
  (app.api as ManagedApiServer).native().addHook('preClose', async () => {
    draining();
  });
  app.api.get('/', {
    schema: { response: schema },
    auth: { required: false },
    handler: async () => {
      entered();
      await gate;
      return await (await app.http.get(origin)).json();
    },
  });
  try {
    await app.start();
    const response = fetch(`http://127.0.0.1:${local.port}/`);
    await ready;
    const stopping = app.stop({ timeoutMs: 1000 });
    await drain;
    released();
    assert.deepEqual(await (await response).json(), { value: 'backend' });
    await stopping;
    assert.equal(app.state, 'CLOSED');
  } finally {
    released();
    await app.stop();
    backend.closeAllConnections();
    await new Promise<void>((resolve) => backend.close(() => resolve()));
  }
});

test('MFA-AUTH-001 assurance routes reject missing or failing provider policy before binding a listener', async () => {
  for (const policy of [
    undefined,
    () => false,
    () => {
      throw new Error('fake-policy-failure');
    },
  ]) {
    const api = createApi({
      service,
      port: 0,
      ...(policy ? { auth: { hasAssurancePolicy: policy } as never } : {}),
    });
    api.get('/protected', {
      ...publicRoute(() => ({ value: 'unreachable' })),
      auth: { required: true, assurance: 'mfa' },
    });
    try {
      await assert.rejects(api.start(), code('EK_MFA_POLICY'));
      assert.equal(api.address(), undefined);
    } finally {
      await api.close();
    }
  }
  const api = createApi({ service, port: 0 });
  try {
    for (const auth of [
      { required: false, assurance: 'mfa' },
      { required: true, assurance: 'unknown' },
    ])
      assert.throws(
        () => api.get('/invalid', { ...publicRoute(() => ({})), auth: auth as never }),
        code('EK_MFA_POLICY'),
      );
    assert.throws(
      () =>
        api.get('/typo', {
          ...publicRoute(() => ({})),
          auth: { required: true, assuranc: 'mfa' } as never,
        }),
      code('EK_CONFIG_INVALID'),
    );
  } finally {
    await api.close();
  }
});

test('MFA-AUTH-001 rate-limit responses expose only bounded integer Retry-After metadata', async () => {
  const api = createApi({ service, port: 0 });
  const values = [1001, 0, -1, 1.5, 86_400_001, 'fake-secret'];
  values.forEach((value, index) =>
    api.get(
      '/rate/' + index,
      publicRoute(() => {
        throw new KitError({
          code: 'EK_MFA_RATE_LIMIT',
          message: 'fake-private-policy',
          details: { retryAfterMs: value },
        });
      }),
    ),
  );
  try {
    await api.start();
    for (const [index] of values.entries()) {
      const reply = await api.native().inject('/rate/' + index);
      assert.equal(reply.statusCode, 429);
      assert.equal(reply.headers['retry-after'], index === 0 ? '2' : undefined);
      assert.ok(!reply.body.includes('fake-'));
    }
  } finally {
    await api.close();
  }
});
