// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  COMPONENTS,
  type ApiServer,
  type Plugin,
  type VerifiedTenantContext,
} from '@arkenivajs/core';
import type { TenantRegistrySnapshotV1_1 } from '../../dist/index.js';
import { request as httpRequest } from 'node:http';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { within } from '@arkenivajs/core/support';
import { fixture, settings, registry, send, tlsFiles } from '../http-fixture.js';
import { connect } from 'node:http2';
import { registryContentChecksum } from '../../dist/registry.js';

test('Real signed identities select exact tenant handlers and never trust diagnostic headers or bodies', async () => {
  const f = await fixture();
  try {
    for (const tenant of ['north', 'south']) {
      const result = await send(f.origin, '/api/orders/order-7', {
        headers: {
          authorization: await f.token(tenant),
          'x-tenant-id': tenant === 'north' ? 'south' : 'north',
        },
      });
      assert.equal(result.status, 200, result.body);
      assert.deepEqual(result.json(), { tenant, implementation: tenant, id: 'order-7' });
    }
    const written = await send(f.origin, '/api/orders', {
      method: 'POST',
      headers: { authorization: await f.token('north') },
      body: { id: 'created', tenant_id: 'south' },
    });
    assert.equal(written.status, 200, written.body);
    assert.equal(written.json().tenant, 'north');
    assert.equal(f.service.api.revision(), 'stable-blue');
    assert.deepEqual(f.service.api.operations(), ['orders.create', 'orders.read']);
    const tenant = await f.tenant();
    assert.equal(f.service.api.resolve('orders.read', tenant)?.implementationId, 'north-orders');
  } finally {
    await f.close();
  }
});

test('Unauthenticated, scope-denied, unmapped and disabled tenants cannot invoke business handlers', async () => {
  let effects = 0;
  const snapshot = registry();
  snapshot.bindings.find(
    (binding) => binding.tenantId === 'south' && binding.operationId === 'orders.read',
  )!.enabled = false;
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  const input = settings(snapshot),
    f = await fixture({
      ...input,
      handlers: {
        north: () => {
          effects++;
          return {};
        },
        south: () => {
          effects++;
          return {};
        },
      },
    });
  try {
    for (const [header, status] of [
      [undefined, 401],
      ['Bearer invalid', 401],
      [await f.token('north', 'unrelated'), 403],
      [await f.token('unknown'), 404],
      [await f.token('south'), 404],
    ] as const) {
      const result = await send(f.origin, '/api/orders/id', {
        headers: header ? { authorization: header } : {},
      });
      assert.equal(result.status, status, result.body);
    }
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});

test('Manually constructed, copied and cross-authority tenant objects never gain provenance', async () => {
  const first = await fixture(),
    second = await fixture();
  try {
    const original = await first.tenant();
    for (const forged of [
      { ...original },
      JSON.parse(JSON.stringify(original)),
      { ...original, tenantId: 'south' },
      await second.tenant(),
    ]) {
      assert.throws(
        () => first.service.api.resolve('orders.read', forged as VerifiedTenantContext),
        { code: 'EK_AUTH_REQUIRED' },
      );
      await assert.rejects(first.service.capabilities.list(forged as VerifiedTenantContext), {
        code: 'EK_AUTH_REQUIRED',
      });
    }
    assert.equal((await first.service.capabilities.list(original)).capabilities.length, 2);
  } finally {
    await Promise.all([first.close(), second.close()]);
  }
});

test('Native JSON input and normalized response contracts fail without exposing payloads or raw errors', async () => {
  let effects = 0;
  const input = settings(),
    f = await fixture({
      ...input,
      handlers: {
        ...input.handlers,
        north: () => {
          effects++;
          return { private: 'must-not-escape' };
        },
      },
    });
  try {
    const authorization = await f.token();
    for (const raw of [
      '{',
      '{"id":"one","id":"two"}',
      '{"__proto__":{"polluted":true},"id":"one"}',
      Buffer.from([0xc0, 0xaf]),
      JSON.stringify({ id: 'x'.repeat(5000) }),
      JSON.stringify({ id: 1 }),
    ]) {
      const result = await send(f.origin, '/api/orders', {
        method: 'POST',
        raw,
        headers: { authorization },
      });
      assert.equal(result.status, 400, result.body);
      assert.equal((result.json().error as { code: string }).code, 'EK_TROUTE_CONTRACT');
    }
    assert.equal(effects, 0);
    const invalid = await send(f.origin, '/api/orders/one', { headers: { authorization } });
    assert.equal(invalid.status, 502, invalid.body);
    assert.doesNotMatch(invalid.body, /must-not-escape|private/);
    assert.doesNotMatch(f.logs(), /must-not-escape/);
  } finally {
    await f.close();
  }
});

test('Capability discovery filters each principal and hides implementation data without accepting tenant selectors', async () => {
  const f = await fixture();
  try {
    const result = await send(f.origin, '/api/tenant/capabilities', {
      headers: { authorization: await f.token('north', 'orders:read') },
    });
    assert.equal(result.status, 200, result.body);
    assert.equal(result.headers['cache-control'], 'private, no-store');
    assert.match(String(result.headers.vary), /Authorization/i);
    const body = result.json();
    assert.equal(body.activationGeneration, 1);
    assert.deepEqual(body.capabilities, [
      {
        operationId: 'orders.read',
        method: 'GET',
        path: '/api/orders/:id',
        label: 'Read an order',
      },
    ]);
    assert.doesNotMatch(result.body, /north-orders|handlerKey|upstream|tenantId/);
    const absent = await send(f.origin, '/api/tenant/capabilities', {
      headers: { authorization: await f.token('unmapped') },
    });
    assert.deepEqual(absent.json().capabilities, []);
    const selector = await send(f.origin, '/api/tenant/capabilities?tenant_id=south', {
      headers: { authorization: await f.token() },
    });
    assert.equal(selector.status, 400, selector.body);
  } finally {
    await f.close();
  }
});

test('Capability limits apply after filtering and overflow never returns a truncated success', async () => {
  const f = await fixture({ ...settings(), maxCapabilities: 1 });
  try {
    const allowed = await send(f.origin, '/api/tenant/capabilities', {
      headers: { authorization: await f.token('north', 'orders:read') },
    });
    assert.equal(allowed.status, 200, allowed.body);
    assert.equal((allowed.json().capabilities as unknown[]).length, 1);
    const overflow = await send(f.origin, '/api/tenant/capabilities', {
      headers: { authorization: await f.token() },
    });
    assert.equal(overflow.status, 503, overflow.body);
    assert.equal((overflow.json().error as { code: string }).code, 'EK_TCAP_LIMIT_EXCEEDED');
    assert.equal(overflow.json().capabilities, undefined);
  } finally {
    await f.close();
  }
});

test('A hidden capability remains executable only under its independent operation authorization', async () => {
  const snapshot = registry();
  Object.assign(
    snapshot.bindings.find(
      (binding) => binding.tenantId === 'north' && binding.operationId === 'orders.create',
    )!,
    { discoverable: false },
  );
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  const f = await fixture(settings(snapshot));
  try {
    const authorization = await f.token(),
      visible = await send(f.origin, '/api/tenant/capabilities', { headers: { authorization } });
    assert.equal(visible.status, 200, visible.body);
    assert.deepEqual(
      (visible.json().capabilities as { operationId: string }[]).map((item) => item.operationId),
      ['orders.read'],
    );
    const executed = await send(f.origin, '/api/orders', {
      method: 'POST',
      body: { id: 'hidden' },
      headers: { authorization },
    });
    assert.equal(executed.status, 200, executed.body);
    const forbidden = await send(f.origin, '/api/orders', {
      method: 'POST',
      body: { id: 'hidden' },
      headers: { authorization: await f.token('north', 'orders:read') },
    });
    assert.equal(forbidden.status, 403, forbidden.body);
  } finally {
    await f.close();
  }
});

test('Capacity is acquired after authorization and retained through timed-out physical handler work', async () => {
  const snapshot = registry();
  snapshot.operations[0]!.maxConcurrency = 1;
  snapshot.operations[0]!.timeoutMs = 200;
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  let enter!: () => void,
    release!: () => void,
    effects = 0,
    signal: AbortSignal | undefined;
  const entered = new Promise<void>((resolve) => {
      enter = resolve;
    }),
    gate = new Promise<void>((resolve) => {
      release = resolve;
    });
  const input = settings(snapshot),
    f = await fixture({
      ...input,
      handlers: {
        ...input.handlers,
        north: async (ctx) => {
          effects++;
          if (effects === 1) {
            signal = ctx.signal;
            enter();
            await gate;
          }
          return { tenant: ctx.auth!.tenantId, implementation: 'north', id: ctx.params.id };
        },
      },
    });
  try {
    const authorization = await f.token(),
      pending = send(f.origin, '/api/orders/first', { headers: { authorization } });
    await within(() => entered, { timeoutMs: 2000 });
    const forbidden = await send(f.origin, '/api/orders/second', {
      headers: { authorization: await f.token('north', 'unrelated') },
    });
    assert.equal(forbidden.status, 403, forbidden.body);
    const otherTenant = await send(f.origin, '/api/orders/third', {
      headers: { authorization: await f.token('south') },
    });
    assert.equal(otherTenant.status, 503, otherTenant.body);
    assert.equal((otherTenant.json().error as { code: string }).code, 'EK_TROUTE_CAPACITY');
    const expired = await pending;
    assert.equal(expired.status, 504, expired.body);
    assert.ok(signal?.aborted);
    assert.equal(
      (await send(f.origin, '/api/orders/fourth', { headers: { authorization } })).status,
      503,
    );
    assert.equal(effects, 1);
    release();
    await nextTurn();
    const accepted = await send(f.origin, '/api/orders/fifth', { headers: { authorization } });
    assert.equal(accepted.status, 200, accepted.body);
    assert.equal(effects, 2);
  } finally {
    release();
    await f.close();
  }
});

test('Client disconnection aborts the owned signal while uncooperative work still consumes its permit', async () => {
  const snapshot = registry();
  snapshot.operations[0]!.maxConcurrency = 1;
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  let enter!: () => void,
    release!: () => void,
    aborted!: () => void,
    effects = 0;
  const entered = new Promise<void>((resolve) => {
      enter = resolve;
    }),
    gate = new Promise<void>((resolve) => {
      release = resolve;
    }),
    cancelled = new Promise<void>((resolve) => {
      aborted = resolve;
    });
  const input = settings(snapshot),
    f = await fixture({
      ...input,
      handlers: {
        ...input.handlers,
        north: async (ctx) => {
          effects++;
          if (effects === 1) {
            ctx.signal.addEventListener('abort', aborted, { once: true });
            enter();
            await gate;
          }
          return { tenant: ctx.auth!.tenantId, implementation: 'north', id: ctx.params.id };
        },
      },
    });
  const outgoing = httpRequest(f.origin + '/api/orders/one', {
    headers: { authorization: await f.token() },
  });
  outgoing.on('error', () => {});
  outgoing.end();
  try {
    await within(() => entered, { timeoutMs: 2000 });
    outgoing.destroy();
    await within(() => cancelled, { timeoutMs: 2000 });
    const blocked = await send(f.origin, '/api/orders/two', {
      headers: { authorization: await f.token() },
    });
    assert.equal(blocked.status, 503, blocked.body);
    release();
    await nextTurn();
    assert.equal(
      (await send(f.origin, '/api/orders/three', { headers: { authorization: await f.token() } }))
        .status,
      200,
    );
  } finally {
    outgoing.destroy();
    release();
    await f.close();
  }
});

test('An incomplete JSON upload is bounded by the operation deadline without invoking a handler', async () => {
  const snapshot = registry();
  snapshot.operations[1]!.timeoutMs = 100;
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  let effects = 0;
  const input = settings(snapshot),
    f = await fixture({
      ...input,
      handlers: {
        ...input.handlers,
        north: () => {
          effects++;
          return {};
        },
      },
    });
  let outgoing: ReturnType<typeof httpRequest> | undefined;
  try {
    const authorization = await f.token();
    const result = new Promise<number>((resolve, reject) => {
      try {
        let received = false;
        outgoing = httpRequest(
          f.origin + '/api/orders',
          {
            method: 'POST',
            headers: {
              authorization,
              'content-type': 'application/json',
              'content-length': '1000',
            },
          },
          (response) => {
            received = true;
            response.resume();
            response.once('end', () => resolve(response.statusCode ?? 0));
            response.once('error', reject);
          },
        );
        outgoing.once('error', (error) => {
          if (!received) reject(error);
        });
        outgoing.write('{');
      } catch (error) {
        reject(error);
      }
    });
    assert.equal(await within(() => result, { timeoutMs: 2000 }), 504);
    assert.equal(effects, 0);
  } finally {
    outgoing?.destroy();
    await f.close();
  }
});

test('Graceful drain completes admitted work while rejecting new requests on the existing listener', async () => {
  let enter!: () => void, release!: () => void;
  const entered = new Promise<void>((resolve) => {
      enter = resolve;
    }),
    gate = new Promise<void>((resolve) => {
      release = resolve;
    });
  const input = settings(),
    f = await fixture({
      ...input,
      handlers: {
        ...input.handlers,
        north: async (ctx) => {
          enter();
          await gate;
          return { tenant: ctx.auth!.tenantId, implementation: 'north', id: ctx.params.id };
        },
      },
    });
  try {
    const authorization = await f.token(),
      request = send(f.origin, '/api/orders/one', { headers: { authorization } });
    await within(() => entered, { timeoutMs: 2000 });
    const stopping = f.app.stop({ timeoutMs: 2000 });
    const rejected = await send(f.origin, '/api/orders/two', { headers: { authorization } });
    assert.equal(rejected.status, 503, rejected.body);
    release();
    assert.equal((await request).status, 200);
    await stopping;
    assert.equal(f.app.state, 'CLOSED');
  } finally {
    release();
    await f.close();
  }
});

test('The default 1000-entry limit counts authorized visible results rather than registry operations', async () => {
  const original = registry(),
    base = original.operations[0]!;
  const operations = Array.from({ length: 1001 }, (_, index) => ({
    ...base,
    id: 'feature.' + String(index).padStart(4, '0'),
    path: '/api/features/' + index,
    schemas: { response: { type: 'null' } },
    policy: { requiredScopes: ['features:read'] },
  }));
  const snapshot: TenantRegistrySnapshotV1_1 = {
    ...original,
    operations,
    implementations: [{ id: 'available', kind: 'handler', handlerKey: 'available' }],
    bindings: operations.map((operation) => ({
      tenantId: 'north',
      operationId: operation.id,
      implementationId: 'available',
      enabled: true,
    })),
    contentChecksum: registryContentChecksum({
      ...original,
      operations,
      implementations: [{ id: 'available', kind: 'handler', handlerKey: 'available' }],
      bindings: operations.map((operation) => ({
        tenantId: 'north',
        operationId: operation.id,
        implementationId: 'available',
        enabled: true,
      })),
    }),
  };
  let visible = 2;
  const f = await fixture({
    ...settings(snapshot),
    handlers: { available: () => null },
    authorize: ({ operationId }) => Number(operationId.split('.')[1]) < visible,
  });
  try {
    const authorization = await f.token('north', 'features:read');
    for (const count of [2, 1000]) {
      visible = count;
      const response = await send(f.origin, '/api/tenant/capabilities', {
        headers: { authorization },
      });
      assert.equal(response.status, 200, response.body);
      assert.equal((response.json().capabilities as unknown[]).length, count);
    }
    visible = 1001;
    const response = await send(f.origin, '/api/tenant/capabilities', {
      headers: { authorization },
    });
    assert.equal(response.status, 503, response.body);
    assert.equal((response.json().error as { code: string }).code, 'EK_TCAP_LIMIT_EXCEEDED');
    assert.equal(response.json().capabilities, undefined);
  } finally {
    await f.close();
  }
});

test('Assurance comes from the verified issuer policy and cannot be upgraded by request headers', async () => {
  const snapshot = registry();
  Object.assign(snapshot.operations[0]!.policy, { assurance: 'mfa' });
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  const f = await fixture(settings(snapshot), {
    assuranceResolver: (identity) =>
      Array.isArray(identity.claims.amr) && identity.claims.amr.includes('otp')
        ? 'mfa'
        : 'single-factor',
  });
  try {
    const denied = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token(), 'x-auth-assurance': 'phishing-resistant' },
    });
    assert.equal(denied.status, 403, denied.body);
    const allowed = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('north', 'orders:read', { amr: ['pwd', 'otp'] }) },
    });
    assert.equal(allowed.status, 200, allowed.body);
  } finally {
    await f.close();
  }
});

test('Authorization provider errors omit capabilities and deny execution without leaking diagnostics', async () => {
  const f = await fixture({
    ...settings(),
    authorize: ({ operationId }) => {
      if (operationId === 'orders.read') throw new Error('private-policy-error');
      return true;
    },
  });
  try {
    const authorization = await f.token(),
      capabilities = await send(f.origin, '/api/tenant/capabilities', {
        headers: { authorization },
      });
    assert.equal(capabilities.status, 200, capabilities.body);
    assert.deepEqual(
      (capabilities.json().capabilities as { operationId: string }[]).map(
        (item) => item.operationId,
      ),
      ['orders.create'],
    );
    const denied = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(denied.status, 403, denied.body);
    assert.doesNotMatch(capabilities.body + denied.body + f.logs(), /private-policy-error/);
  } finally {
    await f.close();
  }
});

test('The registry is loaded once and caller mutations cannot replace a running handler or binding', async () => {
  const snapshot = registry(),
    input = settings(snapshot),
    handlers = { ...input.handlers };
  let loads = 0;
  const f = await fixture({
    ...input,
    handlers,
    registry: {
      loadSnapshot: async () => {
        loads++;
        return snapshot;
      },
    },
  });
  try {
    snapshot.bindings[0]!.implementationId = 'south-orders';
    snapshot.revision = 'changed-outside';
    handlers.north = () => ({ tenant: 'south', implementation: 'changed-outside', id: 'invalid' });
    const result = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token() },
    });
    assert.equal(result.status, 200, result.body);
    assert.equal(result.json().implementation, 'north');
    assert.equal(f.service.api.revision(), 'stable-blue');
    assert.equal(loads, 1);
  } finally {
    await f.close();
  }
});

test('Collisions with existing API routes reject startup before the listener activates', async () => {
  const conflicting: Plugin = {
    id: 'existing-business-route',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['api'],
    init(context) {
      context.require<ApiServer>(COMPONENTS.api).get('/api/orders/:other', {
        schema: { response: {} },
        auth: { required: false },
        handler: () => ({}),
      });
    },
    close() {},
  };
  const contains = (input: unknown): boolean => {
    if (!input || typeof input !== 'object') return false;
    if ('code' in input && input.code === 'EK_TROUTE_COLLISION') return true;
    if (input instanceof AggregateError && input.errors.some(contains)) return true;
    return 'cause' in input && contains(input.cause);
  };
  await assert.rejects(fixture(settings(), { plugins: [conflicting] }), contains);
});

test('Tenant routes share direct HTTPS, HTTP2 streams, HTTP1 fallback and existing REST on one listener', async () => {
  const material = await tlsFiles();
  const existing: Plugin = {
    id: 'existing-rest-route',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['api'],
    init(context) {
      context.require<ApiServer>(COMPONENTS.api).get('/api/existing', {
        schema: {
          response: {
            type: 'object',
            properties: { tenant: { type: 'string' } },
            required: ['tenant'],
            additionalProperties: false,
          },
        },
        auth: { required: true },
        handler: (ctx) => ({ tenant: ctx.auth!.tenantId }),
      });
    },
    close() {},
  };
  let f: Awaited<ReturnType<typeof fixture>> | undefined;
  let session: ReturnType<typeof connect> | undefined;
  try {
    f = await fixture(settings(), { tls: material.tls, http2: true, plugins: [existing] });
    const fallback = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token() },
      ca: material.ca,
    });
    assert.equal(fallback.status, 200, fallback.body);
    assert.equal(fallback.json().tenant, 'north');
    const rest = await send(f.origin, '/api/existing', {
      headers: { authorization: await f.token('south') },
      ca: material.ca,
    });
    assert.equal(rest.status, 200, rest.body);
    assert.equal(rest.json().tenant, 'south');
    session = connect(f.origin, { ca: material.ca });
    session.on('error', () => {});
    const responses = await Promise.all(
      ['north', 'south'].map(async (tenant) => {
        const authorization = await f!.token(tenant);
        return new Promise<{ status: number; tenant: string }>((resolve, reject) => {
          const stream = session!.request({
            ':method': 'GET',
            ':path': '/api/orders/id',
            authorization,
          });
          let status = 0,
            body = '';
          stream.on('response', (headers) => {
            status = Number(headers[':status']);
          });
          stream.setEncoding('utf8');
          stream.on('data', (chunk: string) => {
            body += chunk;
          });
          stream.once('error', reject);
          stream.once('end', () => {
            try {
              resolve({ status, tenant: (JSON.parse(body) as { tenant: string }).tenant });
            } catch (error) {
              reject(error);
            }
          });
          stream.end();
        });
      }),
    );
    assert.deepEqual(responses, [
      { status: 200, tenant: 'north' },
      { status: 200, tenant: 'south' },
    ]);
  } finally {
    session?.destroy();
    await f?.close();
    await material.close();
  }
});
