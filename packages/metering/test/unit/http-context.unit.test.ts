// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, get as rawGet } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type {
  Identity,
  VerifiedTenantContext,
  TenantId,
  MeteringEvent,
  RouteContext,
  AuthService,
} from '@arkenivajs/core';
import { createApi } from '@arkenivajs/api';
import { createHttpClient } from '@arkenivajs/http';
import { createMeter } from '@arkenivajs/metering';

const service = { name: 'http-meter-test', version: '1.0.0', environment: 'test' as const };
const schema = {
  type: 'object',
  properties: { value: { type: 'string' } },
  required: ['value'],
  additionalProperties: false,
};
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function fixture() {
  const contexts = new Map<Identity, VerifiedTenantContext>();
  const identities = new Map<string, Identity>();
  const trusted = new WeakSet<VerifiedTenantContext>();
  for (const id of ['A', 'B', 'untrusted']) {
    const identity: Identity = Object.freeze({
      subject: 'example',
      issuer: 'https://issuer.invalid',
      audience: ['api'],
      scopes: ['read'],
      claims: {},
    });
    const tenant: VerifiedTenantContext = Object.freeze({
      tenantId: ('tenant-' + id) as TenantId,
      identity,
      verifiedAt: new Date().toISOString(),
      source: 'oidc',
    });
    contexts.set(identity, tenant);
    identities.set(id, identity);
    if (id !== 'untrusted') trusted.add(tenant);
  }
  const auth: AuthService & { isVerifiedTenant(value: unknown): value is VerifiedTenantContext } = {
    async verifyBearer(header) {
      if (!header)
        throw new KitError({ code: 'EK_AUTH_REQUIRED', message: 'Authentication required' });
      const identity = identities.get(header.slice(7));
      if (!identity)
        throw new KitError({ code: 'EK_AUTH_INVALID', message: 'Invalid fixture assertion' });
      return identity;
    },
    requireScope(identity, scope) {
      if (!identity.scopes.includes(scope))
        throw new KitError({ code: 'EK_AUTH_FORBIDDEN', message: 'Required scope is absent' });
    },
    requireAssurance() {
      throw new KitError({ code: 'EK_MFA_ASSURANCE_REQUIRED', message: 'No assurance proof' });
    },
    tenantFrom(identity) {
      return contexts.get(identity)!;
    },
    isVerifiedTenant(value): value is VerifiedTenantContext {
      return !!value && typeof value === 'object' && trusted.has(value as VerifiedTenantContext);
    },
  };
  const events: MeteringEvent[] = [];
  const meter = createMeter({
    service,
    auth,
    exporter: {
      kind: 'jsonl',
      async export(batch) {
        events.push(...batch);
      },
      async close() {},
    },
  });
  return { auth, meter, events };
}

test('EK-METER-001 API-owned scopes cover only verified tenant work, retain actual HEAD bytes and exclude health/public traffic', async () => {
  const f = fixture();
  const api = createApi({ service, auth: f.auth, meter: f.meter, port: 0 });
  let middleware = 0;
  api.registerMiddleware('postAuthentication', async (ctx, next) => {
    if (ctx.auth) {
      assert.ok(f.meter.current());
      middleware++;
    }
    await next();
  });
  api.get('/work/:id', {
    schema: { response: schema },
    auth: { required: true, scopes: ['read'] },
    handler: (ctx) => ({ value: ctx.auth!.tenantId }),
  });
  api.get('/public', {
    schema: { response: schema },
    auth: { required: false },
    handler: (ctx) => {
      assert.equal(ctx.auth, undefined);
      assert.equal(f.meter.current(), undefined);
      return { value: 'public' };
    },
  });
  api.get('/denied', {
    schema: { response: schema },
    auth: { required: true, scopes: ['missing'] },
    handler: () => {
      throw new Error('Forbidden handler ran');
    },
  });
  try {
    await api.start();
    const requests = [
      { url: '/work/a', headers: { authorization: 'Bearer A', 'x-request-id': 'forged' } },
      { url: '/work/b', headers: { authorization: 'Bearer B' } },
      { method: 'HEAD' as const, url: '/work/a', headers: { authorization: 'Bearer A' } },
    ];
    const replies = await Promise.all(requests.map((request) => api.native().inject(request)));
    assert.ok(replies.every((reply) => reply.statusCode === 200));
    assert.equal((await api.native().inject('/work/a')).statusCode, 401);
    assert.equal(
      (await api.native().inject({ url: '/work/a', headers: { authorization: 'Bearer wrong' } }))
        .statusCode,
      401,
    );
    assert.equal(
      (
        await api
          .native()
          .inject({ url: '/work/a', headers: { authorization: 'Bearer untrusted' } })
      ).statusCode,
      403,
    );
    assert.equal(
      (await api.native().inject({ url: '/denied', headers: { authorization: 'Bearer A' } }))
        .statusCode,
      403,
    );
    for (const url of ['/public', '/livez', '/readyz'])
      assert.equal((await api.native().inject(url)).statusCode, 200);
    await api.close();
    await f.meter.flush();
    assert.equal(f.events.length, 3);
    assert.equal(middleware, 3);
    for (const event of f.events) {
      assert.equal(event.counters['http.requests']!.value, 1);
      assert.notEqual(event.requestId, 'forged');
      assert.equal(event.quality.complete, true);
    }
    assert.equal(
      f.events.find((event) => event.operation === 'HEAD /work/:id')!.counters[
        'http.response.bytes'
      ]!.value,
      0,
    );
    assert.equal(f.events.filter((event) => event.operation === 'GET /work/:id').length, 2);
    assert.equal(f.meter.snapshot().activeSessions, 0);
  } finally {
    await api.close();
    await f.meter.close();
  }
});

test('EK-METER-001 outbound HTTP records actual client bytes and elapsed scope work while deadlines remain distinct from upstream failures', async () => {
  const f = fixture();
  const upstream = createServer((request, reply) => {
    assert.equal(request.headers.authorization, undefined);
    if (request.url === '/hang') return;
    reply.end('hello');
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const address = upstream.address();
  assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  const client = createHttpClient({
    allowedOrigins: [origin],
    allowPrivateNetwork: true,
    meter: f.meter,
    timeoutMs: 1000,
  });
  const api = createApi({ service, auth: f.auth, meter: f.meter, port: 0, requestTimeoutMs: 500 });
  api.get('/client', {
    schema: { response: schema },
    auth: { required: true },
    handler: async (ctx) => ({
      value: await (await client.get(origin, { signal: ctx.signal })).text(),
    }),
  });
  api.get('/upstream-timeout', {
    schema: { response: schema },
    auth: { required: true },
    handler: async (ctx) => ({
      value: await (
        await client.get(origin + '/hang', { signal: ctx.signal, timeoutMs: 20 })
      ).text(),
    }),
  });
  api.get('/deadline', {
    schema: { response: schema },
    auth: { required: true },
    handler: (ctx: RouteContext) =>
      new Promise((_resolve, reject) =>
        ctx.signal.addEventListener('abort', () => reject(ctx.signal.reason), { once: true }),
      ),
  });
  try {
    await api.start();
    const accepted = await api
      .native()
      .inject({ url: '/client', headers: { authorization: 'Bearer A' } });
    assert.equal(accepted.statusCode, 200);
    assert.equal(
      (
        await api
          .native()
          .inject({ url: '/upstream-timeout', headers: { authorization: 'Bearer A' } })
      ).statusCode,
      504,
    );
    assert.equal(
      (await api.native().inject({ url: '/deadline', headers: { authorization: 'Bearer A' } }))
        .statusCode,
      408,
    );
    await api.close();
    await f.meter.flush();
    assert.equal(f.events.length, 3);
    const actual = f.events.find((event) => event.operation === 'GET /client')!;
    assert.equal(actual.counters['http.client.requests']!.value, 1);
    assert.equal(actual.counters['http.client.response.bytes']!.value, 5);
    assert.ok(actual.counters['http.client.elapsed']!.value >= 0);
    const failed = f.events.find((event) => event.operation === 'GET /upstream-timeout')!;
    assert.equal(failed.status, 'error');
    assert.ok(failed.quality.missing.includes('driver_bytes_unavailable'));
    assert.equal(failed.counters['http.client.response.bytes'], undefined);
    const aborted = f.events.find((event) => event.operation === 'GET /deadline')!;
    assert.equal(aborted.status, 'aborted');
    assert.ok(aborted.quality.missing.includes('aborted_before_close'));
  } finally {
    await api.close();
    await client.close();
    await f.meter.close();
    upstream.closeAllConnections();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
});

test('EK-METER-001 client disconnect completes metering once with unknown bytes and cooperative handler cancellation', async () => {
  const f = fixture();
  const api = createApi({ service, auth: f.auth, meter: f.meter, port: 0 });
  let began!: () => void;
  const started = new Promise<void>((resolve) => {
    began = resolve;
  });
  api.get('/disconnect', {
    schema: { response: schema },
    auth: { required: true },
    handler: (ctx) => {
      began();
      return new Promise((_resolve, reject) =>
        ctx.signal.addEventListener('abort', () => reject(ctx.signal.reason), { once: true }),
      );
    },
  });
  try {
    await api.start();
    const request = rawGet(api.address() + '/disconnect', {
      headers: { authorization: 'Bearer A' },
    });
    request.on('error', () => {});
    await started;
    request.destroy();
    for (let count = 0; count < 100 && f.meter.snapshot().activeSessions > 0; count++)
      await delay(5);
    await api.close();
    await f.meter.flush();
    assert.equal(f.events.length, 1);
    assert.equal(f.events[0]!.status, 'aborted');
    assert.equal(f.events[0]!.counters['http.response.bytes'], undefined);
    assert.ok(f.events[0]!.quality.missing.includes('driver_bytes_unavailable'));
    assert.equal(f.meter.snapshot().activeSessions, 0);
  } finally {
    await api.close();
    await f.meter.close();
  }
});

test('EK-METER-001 closed diagnostics preserve one handler result while unsupported scope providers fail before binding', async () => {
  const f = fixture();
  let calls = 0;
  const api = createApi({ service, auth: f.auth, meter: f.meter, port: 0 });
  api.get('/close', {
    schema: { response: schema },
    auth: { required: true },
    handler: async () => {
      calls++;
      await f.meter.close();
      return { value: 'preserved' };
    },
  });
  try {
    await api.start();
    assert.equal(
      (await api.native().inject({ url: '/close', headers: { authorization: 'Bearer A' } }))
        .statusCode,
      200,
    );
    assert.equal(calls, 1);
    assert.ok(api.stats().observerFailures >= 2);
  } finally {
    await api.close();
    await f.meter.close();
  }
  const closed = createApi({ service, auth: f.auth, meter: f.meter, port: 0 });
  closed.get('/closed', {
    schema: { response: schema },
    auth: { required: true },
    handler: () => ({ value: 'still-preserved' }),
  });
  try {
    await closed.start();
    assert.equal(
      (await closed.native().inject({ url: '/closed', headers: { authorization: 'Bearer A' } }))
        .statusCode,
      200,
    );
    assert.ok(closed.stats().observerFailures > 0);
  } finally {
    await closed.close();
  }
  const missingControls = { ...f.meter, run: undefined };
  const unsupported = createApi({ service, meter: missingControls, port: 0 });
  await assert.rejects(unsupported.start(), code('EK_CONFIG_INVALID'));
  assert.equal(unsupported.address(), undefined);
  await unsupported.close();
});

test('EK-METER-001 failed downstream trace propagation preserves the response while marking lost correlation', async () => {
  const f = fixture();
  const server = createServer((_request, reply) => reply.end('ok'));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  const client = createHttpClient({
    allowedOrigins: [origin],
    allowPrivateNetwork: true,
    meter: f.meter,
    traceHeaders() {
      throw new Error('fake-context-failure');
    },
  });
  try {
    const identity = await f.auth.verifyBearer('Bearer A');
    const tenant = f.auth.tenantFrom(identity);
    const value = await f.meter.measure(
      { tenant, operation: 'downstream' },
      async () => await (await client.get(origin)).text(),
    );
    assert.equal(value, 'ok');
    await f.meter.flush();
    assert.equal(f.events.length, 1);
    assert.equal(f.events[0]!.quality.complete, false);
    assert.deepEqual(f.events[0]!.quality.missing, ['downstream_unobserved']);
    assert.equal(f.events[0]!.counters['http.client.requests']!.value, 1);
    assert.equal(client.stats().observerFailures, 1);
  } finally {
    await client.close();
    await f.meter.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
