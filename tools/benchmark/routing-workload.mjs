// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import Fastify from 'fastify';
import canonicalize from 'canonicalize';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export const ROUTING_COMPARISON = Symbol('routing.comparison');
export const calculatePath = '/api/orders/:id/calculate';
export const capabilitiesPath = '/api/tenant/capabilities';
export const routingIterations = 100;
export const routingWarmupIterations = 20;
const sampled = new WeakMap();

/** Restrict the comparison to its parent-owned issuer and explicit local TLS material. */
export function routingCoordinates(fixture) {
  const issuer = new URL(fixture.issuer);
  assert.equal(issuer.protocol, 'http:');
  assert.equal(issuer.hostname, '127.0.0.1');
  assert.ok(issuer.port && !issuer.username && !issuer.password && !issuer.search && !issuer.hash);
  assert.equal(issuer.pathname, '/');
  for (const name of ['privateKeyFile', 'certificateFile'])
    assert.ok(
      typeof fixture[name] === 'string' &&
        fixture[name].startsWith('/') &&
        !/[\0\r\n]/.test(fixture[name]),
    );
  assert.ok(typeof fixture.ca === 'string' && fixture.ca.length > 0);
  for (const name of ['tenant', 'otherTenant', 'emptyTenant'])
    assert.ok(typeof fixture[name] === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(fixture[name]));
  assert.equal(new Set([fixture.tenant, fixture.otherTenant, fixture.emptyTenant]).size, 3);
}

/** Fixed application catalog; both paths enforce the same JSON contracts and tenant-owned rows. */
export function routingCorpus(fixture) {
  routingCoordinates(fixture);
  const response = {
    type: 'object',
    required: ['found', 'total'],
    additionalProperties: false,
    properties: { found: { type: 'boolean' }, total: { type: 'integer' } },
  };
  const body = {
    type: 'object',
    required: ['amount'],
    additionalProperties: false,
    properties: {
      amount: { type: 'integer', minimum: 0, maximum: 1000 },
      tenantHint: { type: 'string', maxLength: 128 },
      implementationHint: { type: 'string', maxLength: 128 },
    },
  };
  const calculate = {
    id: 'orders.calculate',
    method: 'POST',
    path: calculatePath,
    label: 'Calculate an order',
    schemas: {
      params: {
        type: 'object',
        required: ['id'],
        additionalProperties: false,
        properties: { id: { type: 'string', minLength: 1, maxLength: 128 } },
      },
      body,
      response,
    },
    policy: { requiredScopes: ['orders:write'] },
    maxConcurrency: 4,
    maxBodyBytes: 4096,
    maxResponseBytes: 4096,
    timeoutMs: 3000,
  };
  const operations = [
    calculate,
    {
      ...calculate,
      id: 'orders.status',
      method: 'GET',
      path: '/api/order-status',
      label: 'Read order status',
      schemas: {
        response: {
          type: 'object',
          required: ['ready'],
          additionalProperties: false,
          properties: { ready: { type: 'boolean' } },
        },
      },
      policy: { requiredScopes: ['orders:read'] },
    },
    {
      ...calculate,
      id: 'orders.denied',
      path: '/api/denied',
      label: 'Restricted order action',
      schemas: { body, response },
      policy: { requiredScopes: ['orders:denied'] },
    },
  ];
  const implementations = [
    { id: 'private-north-implementation', kind: 'handler', handlerKey: 'north' },
    { id: 'private-south-implementation', kind: 'handler', handlerKey: 'south' },
    { id: 'private-status-implementation', kind: 'handler', handlerKey: 'status' },
    { id: 'private-denied-implementation', kind: 'handler', handlerKey: 'denied' },
  ];
  const bindings = [fixture.tenant, fixture.otherTenant].flatMap((tenantId) =>
    operations.map((operation) => ({
      tenantId,
      operationId: operation.id,
      implementationId:
        operation.id === calculate.id
          ? implementations[tenantId === fixture.tenant ? 0 : 1].id
          : implementations[operation.id === 'orders.status' ? 2 : 3].id,
      enabled: true,
    })),
  );
  const content = { schemaVersion: '1.1.0', operations, implementations, bindings };
  const registry = {
    ...content,
    revision: 'routing-comparison-content',
    activationGeneration: 7,
    activatedAt: '2026-01-01T00:00:00.000Z',
    contentChecksum:
      'sha256:' + createHash('sha256').update(canonicalize(content), 'utf8').digest('hex'),
  };
  const calls = { north: 0, south: 0, status: 0, denied: 0 };
  const handler = (kind, context) => {
    calls[kind]++;
    if (kind === 'status') return { ready: true };
    if (kind === 'denied') throw new Error('The denied comparison handler must never execute');
    const own = kind === 'north' ? fixture.row : fixture.otherRow;
    assert.equal(context.auth.tenantId, kind === 'north' ? fixture.tenant : fixture.otherTenant);
    return context.params.id === own
      ? { found: true, total: context.body.amount * (kind === 'north' ? 2 : 3) }
      : { found: false, total: 0 };
  };
  return {
    registry,
    handlers: Object.fromEntries(
      Object.keys(calls).map((kind) => [kind, (context) => handler(kind, context)]),
    ),
    authorize: ({ operationId }) => operationId !== 'orders.denied',
    stats: () => ({ ...calls }),
  };
}

async function principal(fixture, keys, assertion) {
  assert.ok(typeof assertion === 'string' && /^Bearer [^\s]+$/.test(assertion));
  const { payload } = await jwtVerify(assertion.slice(7), keys, {
    issuer: fixture.issuer,
    audience: fixture.audience,
    algorithms: ['RS256'],
    requiredClaims: ['sub', 'exp', 'tenant_id'],
  });
  assert.ok([fixture.tenant, fixture.otherTenant, fixture.emptyTenant].includes(payload.tenant_id));
  return {
    tenantId: payload.tenant_id,
    scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [],
  };
}

/** Native reference retains signature, scope, binding and application row checks. */
export async function nativeRouting(fixture) {
  const corpus = routingCorpus(fixture),
    keys = createRemoteJWKSet(new URL('/keys', fixture.issuer));
  const server = Fastify({
    logger: false,
    bodyLimit: 4096,
    https: {
      key: await readFile(fixture.privateKeyFile),
      cert: await readFile(fixture.certificateFile),
    },
  });
  const admitted = new WeakMap();
  const fail = (reply, status, code) => reply.code(status).send({ error: code });
  const selected = (operation, tenant) =>
    corpus.registry.bindings.find(
      (binding) =>
        binding.tenantId === tenant.tenantId &&
        binding.operationId === operation.id &&
        binding.enabled,
    );
  const authorized = (operation, tenant) =>
    operation.policy.requiredScopes.every((scope) => tenant.scopes.includes(scope)) &&
    corpus.authorize({ operationId: operation.id });
  server.addHook('preValidation', async (incoming, reply) => {
    try {
      admitted.set(incoming, await principal(fixture, keys, incoming.headers.authorization));
    } catch {
      return fail(reply, 401, 'EK_AUTH_REQUIRED');
    }
  });
  server.setErrorHandler((error, _incoming, reply) =>
    fail(
      reply,
      error.validation ? 400 : 500,
      error.validation ? 'EK_TROUTE_CONTRACT' : 'EK_TROUTE_UPSTREAM',
    ),
  );
  try {
    for (const operation of corpus.registry.operations)
      server.route({
        method: operation.method,
        url: operation.path,
        schema: {
          ...operation.schemas,
          response: { 200: operation.schemas.response },
        },
        handler(incoming, reply) {
          const tenant = admitted.get(incoming),
            binding = selected(operation, tenant);
          if (!binding) return fail(reply, 404, 'EK_TROUTE_UNMAPPED');
          if (!authorized(operation, tenant)) return fail(reply, 403, 'EK_TROUTE_FORBIDDEN');
          const implementation = corpus.registry.implementations.find(
            (entry) => entry.id === binding.implementationId,
          );
          return corpus.handlers[implementation.handlerKey]({
            auth: tenant,
            params: incoming.params,
            body: incoming.body,
          });
        },
      });
    server.get(capabilitiesPath, (incoming, reply) => {
      reply.header('cache-control', 'private, no-store').header('vary', 'Authorization');
      if (Object.keys(incoming.query).length) return fail(reply, 400, 'EK_TCAP_UNAVAILABLE');
      const tenant = admitted.get(incoming),
        capabilities = corpus.registry.operations
          .filter((operation) => selected(operation, tenant) && authorized(operation, tenant))
          .map(({ id: operationId, method, path, label }) => ({ operationId, method, path, label }))
          .sort((a, b) => a.operationId.localeCompare(b.operationId));
      if (capabilities.length > 1) return fail(reply, 503, 'EK_TCAP_LIMIT_EXCEEDED');
      return {
        schemaVersion: '1.0.0',
        revision: corpus.registry.revision,
        activationGeneration: corpus.registry.activationGeneration,
        capabilities,
      };
    });
    const address = await server.listen({ host: '127.0.0.1', port: 0 });
    return {
      api: { address: () => address },
      stats: corpus.stats,
      registry: corpus.registry,
      async resolution(token) {
        const tenant = await principal(fixture, keys, 'Bearer ' + token);
        const binding = selected(corpus.registry.operations[0], tenant);
        return binding
          ? {
              operationId: binding.operationId,
              implementationId: binding.implementationId,
              revision: corpus.registry.revision,
              activationGeneration: 7,
              kind: 'handler',
            }
          : null;
      },
      close: () => server.close(),
    };
  } catch (error) {
    await server.close();
    throw error;
  }
}

/** Every request uses verified fixture TLS and finite response/body deadlines. */
export function routingRequest(
  service,
  fixture,
  path,
  { token = fixture.token, method = 'GET', body } = {},
) {
  const origin = new URL(service.api.address());
  assert.equal(origin.protocol, 'https:');
  assert.equal(origin.hostname, '127.0.0.1');
  assert.ok(path.startsWith('/') && !path.startsWith('//'));
  return new Promise((resolve, reject) => {
    const outgoing = request(
      new URL(path, origin),
      {
        method,
        agent: false,
        ca: Buffer.from(fixture.ca, 'base64'),
        signal: AbortSignal.timeout(3000),
        headers: {
          'content-type': 'application/json',
          'x-tenant-id': fixture.otherTenant,
          ...(token ? { authorization: 'Bearer ' + token } : {}),
        },
      },
      (incoming) => {
        const chunks = [];
        let bytes = 0;
        incoming.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 16384) incoming.destroy(new Error('The routing receipt exceeded its bound'));
          else chunks.push(chunk);
        });
        incoming.once('error', reject);
        incoming.once('end', () => {
          try {
            resolve({
              status: incoming.statusCode,
              headers: incoming.headers,
              body: JSON.parse(Buffer.concat(chunks).toString()),
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    outgoing.once('error', reject);
    outgoing.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

export async function verifyRouting(service, fixture) {
  const calculate = '/api/orders/' + fixture.row + '/calculate';
  const payload = {
    amount: 7,
    tenantHint: fixture.otherTenant,
    implementationHint: fixture.implementationHint,
  };
  const send = (path, options) => routingRequest(service, fixture, path, options);
  const success = async (path, options) => {
    const result = await send(path, options);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    return result.body;
  };
  for (const token of ['', fixture.invalidToken, fixture.foreignToken])
    assert.equal((await send(calculate, { token, method: 'POST', body: payload })).status, 401);
  assert.equal(
    (await send(calculate, { token: fixture.unscopedToken, method: 'POST', body: payload })).status,
    403,
  );
  assert.equal((await send('/api/denied', { method: 'POST', body: payload })).status, 403);
  assert.equal(
    (await send(calculate, { method: 'POST', body: { amount: 'invalid' } })).status,
    400,
  );
  assert.equal((await send('/api/order-status')).status, 403);
  assert.deepEqual(service.stats(), { north: 0, south: 0, status: 0, denied: 0 });
  assert.deepEqual(await success(calculate, { method: 'POST', body: payload }), {
    found: true,
    total: 14,
  });
  assert.deepEqual(
    await success('/api/orders/' + fixture.otherRow + '/calculate', {
      token: fixture.otherToken,
      method: 'POST',
      body: payload,
    }),
    { found: true, total: 21 },
  );
  assert.deepEqual(
    await success('/api/orders/' + fixture.otherRow + '/calculate', {
      method: 'POST',
      body: payload,
    }),
    { found: false, total: 0 },
  );
  assert.equal(
    (await send(calculate, { token: fixture.emptyToken, method: 'POST', body: payload })).status,
    404,
  );
  for (const token of [
    fixture.token,
    fixture.otherToken,
    fixture.unscopedToken,
    fixture.emptyToken,
  ]) {
    const result = await send(capabilitiesPath, { token });
    assert.equal(result.status, 200);
    assert.equal(result.headers['cache-control'], 'private, no-store');
    assert.match(result.headers.vary, /Authorization/i);
    const expected =
      token === fixture.token || token === fixture.otherToken
        ? [
            {
              operationId: 'orders.calculate',
              method: 'POST',
              path: calculatePath,
              label: 'Calculate an order',
            },
          ]
        : [];
    assert.deepEqual(result.body, {
      schemaVersion: '1.0.0',
      revision: 'routing-comparison-content',
      activationGeneration: 7,
      capabilities: expected,
    });
    assert.doesNotMatch(
      JSON.stringify(result.body),
      /handlerKey|implementationId|private-|upstream|tenantId/,
    );
  }
  assert.equal((await send(capabilitiesPath + '?tenant_id=' + fixture.otherTenant)).status, 400);
  const exceeded = await send(capabilitiesPath, { token: fixture.expandedToken });
  assert.equal(exceeded.status, 503);
  assert.match(JSON.stringify(exceeded.body), /EK_TCAP_LIMIT_EXCEEDED/);
  assert.equal(exceeded.body.capabilities, undefined);
  assert.deepEqual(await success('/api/order-status', { token: fixture.expandedToken }), {
    ready: true,
  });
  assert.deepEqual(await success(calculate, { method: 'POST', body: { amount: 3 } }), {
    found: true,
    total: 6,
  });
  for (const [token, implementationId] of [
    [fixture.token, 'private-north-implementation'],
    [fixture.otherToken, 'private-south-implementation'],
  ])
    assert.deepEqual(await service.resolution(token), {
      operationId: 'orders.calculate',
      implementationId,
      revision: 'routing-comparison-content',
      activationGeneration: 7,
      kind: 'handler',
    });
  assert.deepEqual(service.stats(), { north: 3, south: 1, status: 1, denied: 0 });
  return {
    actualHttpsRequests: 19,
    deniedBeforeHandler: 7,
    handlerExecutions: 5,
    tenantImplementations: 2,
    foreignRowAbsent: true,
    emptyTenantHasNoFallback: true,
    capabilityLimit: 1,
    capabilityOverflowRejected: true,
    stableRevisionAndGeneration: true,
  };
}

/** Small closed-loop HTTPS callbacks retain all authentication, schema and receipt checks. */
export function routingWorkload(service, fixture) {
  assert.equal(sampled.has(service), false, 'A comparison service owns one bounded workload');
  const state = {
    baseline: service.stats(),
    completed: { 'local-dispatch': 0, 'capability-discovery': 0, 'authorized-status': 0 },
    running: false,
  };
  sampled.set(service, state);
  const operation = (name, path, options, expected) => async () => {
    assert.equal(state.running, false, 'Routing sampling is sequential closed-loop work');
    assert.ok(
      state.completed[name] < routingIterations + routingWarmupIterations,
      'The routing callback count exceeded its bounded campaign',
    );
    state.running = true;
    try {
      const response = await routingRequest(service, fixture, path, options);
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.deepEqual(response.body, expected);
      if (name === 'capability-discovery') {
        assert.equal(response.headers['cache-control'], 'private, no-store');
        assert.match(response.headers.vary, /Authorization/i);
      }
      state.completed[name]++;
      return response.body;
    } finally {
      state.running = false;
    }
  };
  return {
    'local-dispatch': operation(
      'local-dispatch',
      '/api/orders/' + fixture.row + '/calculate',
      {
        method: 'POST',
        body: {
          amount: 7,
          tenantHint: fixture.otherTenant,
          implementationHint: fixture.implementationHint,
        },
      },
      { found: true, total: 14 },
    ),
    'capability-discovery': operation(
      'capability-discovery',
      capabilitiesPath,
      {},
      {
        schemaVersion: '1.0.0',
        revision: 'routing-comparison-content',
        activationGeneration: 7,
        capabilities: [
          {
            operationId: 'orders.calculate',
            method: 'POST',
            path: calculatePath,
            label: 'Calculate an order',
          },
        ],
      },
    ),
    'authorized-status': operation(
      'authorized-status',
      '/api/order-status',
      { token: fixture.expandedToken },
      { ready: true },
    ),
  };
}

/** Compare independent native handler counters with completed callbacks and retained bench records. */
export function completeRoutingWorkload(service, { measure, records }) {
  const state = sampled.get(service);
  if (!measure) {
    assert.equal(state, undefined);
    assert.equal(records.length, 0);
    assert.deepEqual(service.stats(), { north: 3, south: 1, status: 1, denied: 0 });
    return {
      completedSampleCallbacks: 0,
      expectedUsageChildren: Object.values(service.stats()).reduce((sum, count) => sum + count, 0),
    };
  }
  assert.ok(state && !state.running);
  assert.deepEqual(
    records.map((record) => record.operation),
    Object.keys(state.completed),
  );
  for (const record of records) {
    assert.equal(record.sampleCount, routingIterations);
    assert.equal(record.warmupIterations, routingWarmupIterations);
    assert.equal(state.completed[record.operation], record.sampleCount + record.warmupIterations);
    assert.equal(record.rawLatency?.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
  }
  assert.deepEqual(service.stats(), {
    ...state.baseline,
    north: state.baseline.north + state.completed['local-dispatch'],
    status: state.baseline.status + state.completed['authorized-status'],
  });
  const completedSampleCallbacks = Object.values(state.completed).reduce(
    (sum, count) => sum + count,
    0,
  );
  return {
    completedSampleCallbacks,
    expectedUsageChildren:
      Object.values(state.baseline).reduce((sum, count) => sum + count, 0) +
      state.completed['local-dispatch'] +
      state.completed['authorized-status'],
  };
}
