// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import type { TenantUpstreamCredentials } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings, tlsFiles } from '../http-fixture.js';

test('Invalid credential data and expiry never reach a trusted HTTPS target or poison subsequent authorized work', async (t) => {
  const material = await tlsFiles();
  t.after(() => material.close());
  const authorizationHeader = 'Bearer ' + randomBytes(24).toString('base64url'),
    received: string[] = [],
    upstream = createServer(
      {
        key: await readFile(material.tls.privateKeyFile),
        cert: await readFile(material.tls.certificateFile),
      },
      (request, response) => {
        received.push(request.headers.authorization ?? '');
        assert.equal(request.url, '/fixed');
        assert.equal(request.headers.authorization, authorizationHeader);
        assert.equal(request.headers.cookie, undefined);
        assert.equal(request.headers['x-tenant-id'], undefined);
        response.setHeader('content-type', 'application/json');
        response.end('{"id":"accepted","tenant":"south","implementation":"partner"}');
      },
    );
  await new Promise<void>((done) => upstream.listen(0, '127.0.0.1', done));
  t.after(async () => {
    upstream.closeAllConnections();
    await new Promise<void>((done) => upstream.close(() => done()));
  });
  const address = upstream.address();
  assert.ok(address && typeof address === 'object');
  const original = registry(),
    content = {
      ...original,
      implementations: [
        original.implementations[0]!,
        {
          id: 'south-orders',
          kind: 'http' as const,
          upstreamKey: 'partner',
          upstreamPath: '/fixed',
          method: 'GET' as const,
        },
      ],
    },
    valid: TenantUpstreamCredentials = {
      authorizationHeader,
      audience: 'api://partner',
      scopes: ['orders:read'],
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };
  let returned: unknown = valid,
    providerCalls = 0,
    executableEffects = 0;
  const f = await fixture({
    ...settings({ ...content, contentChecksum: registryContentChecksum(content) }),
    approvedUpstreams: [
      {
        key: 'partner',
        origin: 'https://127.0.0.1:' + address.port,
        allowedHostnames: ['127.0.0.1'],
        allowedCidrs: ['127.0.0.1/32'],
        tlsCaFile: material.tls.certificateFile,
        connectionTimeoutMs: 1000,
        allowRedirects: false,
        serviceAuth: { audience: valid.audience, scopes: valid.scopes },
      },
    ],
    credentialProvider: {
      async get(input, options) {
        providerCalls++;
        assert.equal(input.upstreamKey, 'partner');
        assert.equal(input.audience, valid.audience);
        assert.deepEqual(input.scopes, valid.scopes);
        assert.equal(input.operationId, 'orders.read');
        assert.equal(input.tenant.tenantId, 'south');
        assert.ok(options?.signal);
        return returned as TenantUpstreamCredentials;
      },
    },
  });
  t.after(() => f.close());
  const forgedGetter = Object.defineProperty({ ...valid }, 'expiresAt', {
      enumerable: true,
      get() {
        executableEffects++;
        return valid.expiresAt;
      },
    }),
    trap = () => {
      executableEffects++;
      throw new Error('Credential proxy traps must not execute');
    },
    forgedProxy = new Proxy(valid, {
      ownKeys: trap,
      getOwnPropertyDescriptor: trap,
      getPrototypeOf: trap,
      get(_target, key) {
        // Promise resolution inspects then before the provider result reaches the adapter.
        if (key === 'then') return undefined;
        return trap();
      },
    }),
    credentials: readonly unknown[] = [
      { ...valid, expiresAt: 'private-malformed-expiry' },
      { ...valid, expiresAt: '2099-02-30T00:00:00.000Z' },
      { ...valid, expiresAt: '2099-01-01T00:00:00.1234567890Z' },
      { ...valid, scopes: ['orders:read', 'orders:read'] },
      { ...valid, scopes: 'orders:read' },
      { ...valid, authorizationHeader: 'Digest private-unsupported-scheme' },
      { ...valid, authorizationHeader: 'Bearer ' + 'x'.repeat(8192) },
      forgedGetter,
      forgedProxy,
    ];
  const authorization = await f.token('south'),
    headers = { authorization, cookie: 'private-cookie=value', 'x-tenant-id': 'north' };
  for (returned of credentials) {
    const denied = await send(f.origin, '/api/orders/item', { headers });
    assert.equal(denied.status, 503, denied.body);
    assert.equal((denied.json().error as { code: string }).code, 'EK_TROUTE_UPSTREAM');
    assert.equal(received.length, 0);
    assert.doesNotMatch(
      denied.body,
      /private-|Bearer|Digest|2099|127\.0\.0\.1|orders:read|api:\/\/partner/,
    );
  }
  assert.equal(executableEffects, 0);
  returned = valid;
  const recovered = await send(f.origin, '/api/orders/item', { headers });
  assert.equal(recovered.status, 200, recovered.body);
  assert.deepEqual(recovered.json(), {
    id: 'accepted',
    tenant: 'south',
    implementation: 'partner',
  });
  assert.deepEqual(received, [authorizationHeader]);
  assert.equal(providerCalls, credentials.length + 1);
  assert.equal(executableEffects, 0);
  assert.doesNotMatch(
    f.logs(),
    /private-malformed-expiry|private-unsupported-scheme|private-cookie|Credential proxy traps/,
  );
  assert.ok(!f.logs().includes(authorizationHeader));
  assert.ok(!f.logs().includes(authorization));
});
