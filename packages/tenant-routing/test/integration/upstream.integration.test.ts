// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { TenantRegistrySnapshotV1_1, TenantRoutingPluginSettings } from '../../dist/index.js';
import { fixture, registry, settings, send, tlsFiles } from '../http-fixture.js';
import { registryContentChecksum } from '../../dist/registry.js';

async function upstream(secure = false) {
  const material = secure ? await tlsFiles() : undefined;
  const requests: {
    method: string;
    path: string;
    headers: import('node:http').IncomingHttpHeaders;
    body: string;
  }[] = [];
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let expectedAuthorization: string | undefined;
  let reply: {
    status: number;
    body: string | Buffer;
    type?: string;
    headers?: Record<string, string>;
    delay?: number;
  } = { status: 200, body: '{"reference":"partner-order"}', type: 'application/json' };
  const handle: import('node:http').RequestListener = (request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      requests.push({
        method: request.method ?? '',
        path: request.url ?? '',
        headers: request.headers,
        body: Buffer.concat(chunks).toString(),
      });
      const answer = reply;
      const finish = () => {
        if (expectedAuthorization && request.headers.authorization !== expectedAuthorization) {
          response.statusCode = 401;
          response.end();
          return;
        }
        response.statusCode = answer.status;
        if (answer.type) response.setHeader('content-type', answer.type);
        for (const [key, value] of Object.entries(answer.headers ?? {}))
          response.setHeader(key, value);
        response.end(answer.body);
      };
      if (answer.delay) {
        const timer = setTimeout(() => {
          timers.delete(timer);
          finish();
        }, answer.delay);
        timers.add(timer);
        response.once('close', () => {
          clearTimeout(timer);
          timers.delete(timer);
        });
      } else finish();
    });
  };
  const server = material
    ? createHttpsServer(
        {
          key: await readFile(material.tls.privateKeyFile),
          cert: await readFile(material.tls.certificateFile),
        },
        handle,
      )
    : createServer(handle);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    origin: (secure ? 'https' : 'http') + '://127.0.0.1:' + address.port,
    requests,
    caFile: material?.tls.certificateFile,
    expectAuthorization(value: string) {
      expectedAuthorization = value;
    },
    reply(value: typeof reply) {
      reply = value;
    },
    async close() {
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await material?.close();
    },
  };
}
function partner(
  origin: string,
  options: { caFile?: string; serviceAuth?: boolean; legacy?: boolean } = {},
): TenantRoutingPluginSettings {
  const original = registry();
  const content = {
    ...original,
    implementations: [
      original.implementations[0]!,
      {
        id: 'south-orders',
        kind: 'http' as const,
        upstreamKey: 'partner',
        upstreamPath: '/fixed',
        method: 'POST' as const,
        requestTransformerKey: 'partner-input',
        ...(options.legacy
          ? { transformerKey: 'partner-output' }
          : { responseTransformerKey: 'partner-output' }),
      },
    ],
  };
  const snapshot: TenantRegistrySnapshotV1_1 = {
    ...content,
    contentChecksum: registryContentChecksum(content),
  };
  return {
    ...settings(snapshot),
    approvedUpstreams: [
      {
        key: 'partner',
        origin,
        allowedHostnames: ['127.0.0.1'],
        allowedCidrs: ['127.0.0.1/32'],
        connectionTimeoutMs: 1000,
        allowRedirects: false,
        ...(options.caFile ? { tlsCaFile: options.caFile } : {}),
        ...(options.serviceAuth
          ? { serviceAuth: { audience: 'api://partner', scopes: ['partner:write'] } }
          : {}),
      },
    ],
    requestTransformers: {
      'partner-input': (payload, context) => ({
        ref: context.params.id ?? (payload as { id: string }).id,
      }),
    },
    responseTransformers: {
      'partner-output': (payload, context) => ({
        id: (payload as { reference: string }).reference,
        tenant: context.auth!.tenantId,
        implementation: 'partner',
      }),
    },
  };
}

test('The same public operation selects a fixed partner with separate normalized transforms and no user header delegation', async () => {
  const target = await upstream(),
    f = await fixture(partner(target.origin));
  try {
    const local = await send(f.origin, '/api/orders/local', {
      headers: { authorization: await f.token('north') },
    });
    assert.equal(local.status, 200, local.body);
    assert.equal(target.requests.length, 0);
    const remote = await send(f.origin, '/api/orders/remote', {
      headers: {
        authorization: await f.token('south'),
        'x-tenant-id': 'north',
        cookie: 'private=not-forwarded',
        'proxy-authorization': 'not-forwarded',
      },
    });
    assert.equal(remote.status, 200, remote.body);
    assert.deepEqual(remote.json(), {
      id: 'partner-order',
      tenant: 'south',
      implementation: 'partner',
    });
    assert.equal(target.requests.length, 1);
    assert.equal(target.requests[0]!.method, 'POST');
    assert.equal(target.requests[0]!.path, '/fixed');
    assert.deepEqual(JSON.parse(target.requests[0]!.body), { ref: 'remote' });
    for (const name of ['authorization', 'cookie', 'proxy-authorization', 'x-tenant-id'])
      assert.equal(target.requests[0]!.headers[name], undefined);
  } finally {
    await f.close();
    await target.close();
  }
});

test('Unknown destinations, absent transforms and unsafe destination catalogs fail before listener activation', async () => {
  const target = await upstream();
  try {
    const base = partner(target.origin),
      approved = base.approvedUpstreams![0]!;
    for (const input of [
      { ...base, approvedUpstreams: [] },
      { ...base, requestTransformers: {} },
      { ...base, responseTransformers: {} },
      { ...base, approvedUpstreams: [{ ...approved, allowRedirects: true }] },
      { ...base, approvedUpstreams: [{ ...approved, forwardClientAuthorization: true }] },
      { ...base, approvedUpstreams: [{ ...approved, allowedHostnames: ['unrelated.test'] }] },
      { ...base, approvedUpstreams: [{ ...approved, allowedCidrs: ['10.0.0.0/8'] }] },
      { ...base, approvedUpstreams: [{ ...approved, origin: target.origin + '/private' }] },
      {
        ...base,
        approvedUpstreams: [
          { ...approved, serviceAuth: { audience: 'api://partner', scopes: [] } },
        ],
      },
    ])
      await assert.rejects(fixture(input as TenantRoutingPluginSettings));
    assert.equal(target.requests.length, 0);
  } finally {
    await target.close();
  }
});

test('A GET transform encodes only bounded query values under the fixed approved path', async () => {
  const target = await upstream();
  const base = partner(target.origin),
    snapshot = await base.registry.loadSnapshot(),
    content = {
      ...snapshot,
      implementations: snapshot.implementations.map((implementation) =>
        implementation.kind === 'http'
          ? { ...implementation, method: 'GET' as const }
          : implementation,
      ),
    };
  const f = await fixture({
    ...base,
    registry: {
      loadSnapshot: async () => ({ ...content, contentChecksum: registryContentChecksum(content) }),
    },
    requestTransformers: {
      'partner-input': (_payload, context) => ({
        id: context.params.id,
        list: ['a&b', 'https://unrelated.test/private'],
      }),
    },
  });
  try {
    const result = await send(f.origin, '/api/orders/safe', {
      headers: { authorization: await f.token('south') },
    });
    assert.equal(result.status, 200, result.body);
    const actual = target.requests[0]!,
      url = new URL(actual.path, target.origin);
    assert.equal(actual.method, 'GET');
    assert.equal(actual.body, '');
    assert.equal(url.pathname, '/fixed');
    assert.equal(url.searchParams.get('id'), 'safe');
    assert.deepEqual(url.searchParams.getAll('list'), ['a&b', 'https://unrelated.test/private']);
  } finally {
    await f.close();
    await target.close();
  }
});

test('An upstream deadline cancels the native request and later work can reuse its operation capacity', async () => {
  const target = await upstream(),
    base = partner(target.origin),
    snapshot = await base.registry.loadSnapshot(),
    content = {
      ...snapshot,
      operations: snapshot.operations.map((operation) => ({
        ...operation,
        timeoutMs: 100,
        maxConcurrency: 1,
      })),
    },
    f = await fixture({
      ...base,
      registry: {
        loadSnapshot: async () => ({
          ...content,
          contentChecksum: registryContentChecksum(content),
        }),
      },
    });
  try {
    const authorization = await f.token('south');
    target.reply({
      status: 200,
      body: '{"reference":"late"}',
      type: 'application/json',
      delay: 1000,
    });
    const expired = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(expired.status, 504, expired.body);
    target.reply({ status: 200, body: '{"reference":"recovered"}', type: 'application/json' });
    let result = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    for (let attempt = 0; result.status === 503 && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
      result = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    }
    assert.equal(result.status, 200, result.body);
    assert.equal(result.json().id, 'recovered');
  } finally {
    await f.close();
    await target.close();
  }
});

test('Legacy response aliases remain response-only while the fixed upstream never follows redirects', async () => {
  const target = await upstream(),
    f = await fixture(partner(target.origin, { legacy: true }));
  try {
    const authorization = await f.token('south'),
      accepted = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(accepted.status, 200, accepted.body);
    target.reply({
      status: 302,
      body: '',
      headers: { location: target.origin + '/private-redirect' },
    });
    const denied = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(denied.status, 503, denied.body);
    assert.equal(target.requests.length, 2);
    assert.ok(target.requests.every((request) => request.path === '/fixed'));
    assert.doesNotMatch(denied.body, /private-redirect|127\.0\.0\.1/);
  } finally {
    await f.close();
    await target.close();
  }
});

test('Partner response media, UTF-8, JSON and final schema failures are sanitized contract errors', async () => {
  const target = await upstream(),
    f = await fixture(partner(target.origin));
  try {
    const authorization = await f.token('south');
    for (const answer of [
      { status: 200, body: 'private-upstream-text', type: 'text/plain' },
      { status: 200, body: Buffer.from([0xc0, 0xaf]), type: 'application/json' },
      { status: 200, body: '{"reference":"one","reference":"two"}', type: 'application/json' },
      { status: 200, body: '{"reference":123}', type: 'application/json' },
      { status: 200, body: 'x'.repeat(5000), type: 'application/json' },
      {
        status: 200,
        body: 'x'.repeat(5000),
        type: 'application/json',
        headers: { 'transfer-encoding': 'chunked' },
      },
    ]) {
      target.reply(answer);
      const result = await send(f.origin, '/api/orders/id', { headers: { authorization } });
      assert.equal(result.status, 502, result.body);
      assert.equal((result.json().error as { code: string }).code, 'EK_TROUTE_CONTRACT');
      assert.doesNotMatch(result.body, /private-upstream-text|reference|127\.0\.0\.1/);
    }
  } finally {
    await f.close();
    await target.close();
  }
});

test('An untrusted real TLS certificate fails closed without accepting a partner response', async () => {
  const target = await upstream(true),
    f = await fixture(partner(target.origin));
  try {
    const denied = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('south') },
    });
    assert.equal(denied.status, 503, denied.body);
    assert.equal(target.requests.length, 0);
    assert.doesNotMatch(denied.body, /certificate|127\.0\.0\.1|self.signed/i);
  } finally {
    await f.close();
    await target.close();
  }
});

test('Only audience/scope-bound unexpired provider credentials reach the independently checked TLS target', async () => {
  const target = await upstream(true),
    expected = 'Bearer ' + randomBytes(24).toString('base64url');
  const input = partner(target.origin, { caFile: target.caFile!, serviceAuth: true });
  target.expectAuthorization(expected);
  let mode = 'valid',
    calls = 0;
  const f = await fixture({
    ...input,
    credentialProvider: {
      async get(request) {
        calls++;
        assert.equal(request.upstreamKey, 'partner');
        assert.equal(request.audience, 'api://partner');
        assert.deepEqual(request.scopes, ['partner:write']);
        assert.equal(request.tenant.tenantId, 'south');
        if (mode === 'outage') throw new Error('private-provider-failure');
        return {
          authorizationHeader: mode === 'header' ? expected + '\r\nx-private: injected' : expected,
          expiresAt: new Date(Date.now() + (mode === 'expired' ? -1000 : 60000)).toISOString(),
          audience: mode === 'audience' ? 'api://unrelated' : request.audience,
          scopes: mode === 'scope' ? ['unrelated'] : request.scopes,
        };
      },
    },
  });
  try {
    const authorization = await f.token('south'),
      accepted = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(accepted.status, 200, accepted.body);
    assert.equal(target.requests[0]!.headers.authorization, expected);
    assert.notEqual(expected, authorization);
    for (mode of ['audience', 'scope', 'expired', 'header', 'outage']) {
      const denied = await send(f.origin, '/api/orders/id', { headers: { authorization } });
      assert.equal(denied.status, 503, denied.body);
      assert.equal(target.requests.length, 1);
      assert.doesNotMatch(denied.body, /private-provider-failure|unrelated|Bearer/);
    }
    assert.equal(calls, 6);
    assert.doesNotMatch(f.logs(), /private-provider-failure/);
  } finally {
    await f.close();
    await target.close();
  }
});

test('Credentials expiring during an actual upstream request abort it rather than accepting a late response', async () => {
  const target = await upstream(true),
    expected = 'Bearer ' + randomBytes(24).toString('base64url');
  target.expectAuthorization(expected);
  target.reply({
    status: 200,
    body: '{"reference":"too-late"}',
    type: 'application/json',
    delay: 1000,
  });
  const f = await fixture({
    ...partner(target.origin, { caFile: target.caFile!, serviceAuth: true }),
    credentialProvider: {
      async get(request) {
        return {
          authorizationHeader: expected,
          audience: request.audience,
          scopes: request.scopes,
          expiresAt: new Date(Date.now() + 150).toISOString(),
        };
      },
    },
  });
  try {
    const denied = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('south') },
    });
    assert.equal(denied.status, 503, denied.body);
    assert.equal(target.requests.length, 1);
    assert.doesNotMatch(denied.body, /too-late|Bearer/);
  } finally {
    await f.close();
    await target.close();
  }
});

test('Oversized or executable transformed payloads fail before any network side effect', async () => {
  const target = await upstream();
  let payload: unknown,
    effects = 0;
  const f = await fixture({
    ...partner(target.origin),
    requestTransformers: { 'partner-input': () => payload },
  });
  try {
    const authorization = await f.token('south');
    for (payload of [
      { text: 'x'.repeat(4097) },
      { value: BigInt(1) },
      Object.defineProperty({}, 'secret', {
        enumerable: true,
        get() {
          effects++;
          return 'private';
        },
      }),
    ]) {
      const denied = await send(f.origin, '/api/orders/id', { headers: { authorization } });
      assert.equal(denied.status, 502, denied.body);
    }
    assert.equal(effects, 0);
    assert.equal(target.requests.length, 0);
  } finally {
    await f.close();
    await target.close();
  }
});
