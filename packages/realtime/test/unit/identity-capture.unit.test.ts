// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { FastifyRequest } from 'fastify';
import { capture } from '../../dist/settings.js';
import { requestIdentity, verifiedTenant } from '../../dist/identity.js';
import { fixture } from '../fixture.js';

test('Native request header capture bounds actual UTF8 bytes and preserves immutable duplicate-header and origin semantics', () => {
  const settings = capture({
    routes: [],
    websocketHandlers: {},
    sseSources: {},
    policies: {},
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
    allowedOrigins: ['https://owned.example'],
  });
  const request = (headers: Record<string, string | string[] | undefined>) =>
    ({
      method: 'GET',
      headers,
      routeOptions: {},
    }) as unknown as FastifyRequest;
  const values = ['first', 'second'];
  const input = request({
    'x-duplicate': values,
    'x-absent': undefined,
    origin: 'https://owned.example',
    cookie: 'owned=synthetic',
  });
  const snapshot = requestIdentity(input, settings);
  values[0] = 'changed';
  assert.equal(snapshot.path, '');
  assert.equal(snapshot.headers['x-duplicate'], 'first,second');
  assert.equal(snapshot.headers['x-absent'], undefined);
  assert.ok(Object.isFrozen(snapshot) && Object.isFrozen(snapshot.headers));
  assert.equal(
    requestIdentity(request({ x: 'x'.repeat(32767) }), settings).headers.x?.length,
    32767,
  );
  for (const value of ['x'.repeat(32768), 'π'.repeat(16384)])
    assert.throws(() => requestIdentity(request({ x: value }), settings), {
      code: 'EK_REALTIME_AUTH',
    });
  for (const headers of [
    { cookie: 'owned=synthetic' },
    { origin: 'https://foreign.example' },
    { origin: 'https://foreign.example', cookie: 'owned=synthetic' },
  ])
    assert.throws(() => requestIdentity(request(headers), settings), { code: 'EK_AUTH_FORBIDDEN' });
});

test('Actual verifier-owned tenant context cannot be replaced by a proxy, inherited identity or executable descriptor', async () => {
  const f = await fixture();
  let effects = 0;
  try {
    const auth = f.app.auth!,
      tenant = auth.tenantFrom(await auth.verifyBearer(await f.token()));
    assert.equal(verifiedTenant(auth, tenant), true);
    const hostile = () => {
      effects++;
      throw new Error('Tenant reflection must not execute');
    };
    for (const value of [
      undefined,
      null,
      1,
      'tenant-a',
      () => tenant,
      {},
      { ...tenant },
      { identity: { ...tenant.identity } },
      Object.create({ identity: tenant.identity }),
      Object.defineProperty({}, 'identity', { get: hostile }),
      new Proxy(tenant, {
        get: hostile,
        getOwnPropertyDescriptor: hostile,
        getPrototypeOf: hostile,
      }),
    ])
      assert.equal(verifiedTenant(auth, value), false);
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});
