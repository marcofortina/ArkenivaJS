// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { COMPONENTS, type Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { TENANT_ROUTING_CAPABILITY } from '../../dist/index.js';
import { fixture, send, settings } from '../http-fixture.js';

function collision(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  if ('code' in error && error.code === 'EK_TROUTE_COLLISION') return true;
  if (error instanceof AggregateError && error.errors.some(collision)) return true;
  return 'cause' in error && collision(error.cause);
}

for (const candidate of [
  { method: 'HEAD' as const, path: '/api/orders/:alias', capabilitiesPath: undefined },
  { method: 'GET' as const, path: '/api/tenant/capabilities', capabilitiesPath: undefined },
  {
    method: 'POST' as const,
    path: '/api/private-discovery',
    capabilitiesPath: '/api/private-discovery',
  },
])
  test(`A later plugin cannot replace reserved ${candidate.method} ${candidate.path} before listen`, async () => {
    let attempted = 0,
      effects = 0,
      native: ReturnType<ManagedApiServer['native']> | undefined;
    const late: Plugin = {
      id: 'late-conflicting-route',
      version: '1.0.0',
      capabilities: new Set(),
      dependencies: ['api', 'tenant-routing'],
      init(context) {
        context.require(TENANT_ROUTING_CAPABILITY);
        native = context.require<ManagedApiServer>(COMPONENTS.api).native();
        assert.equal(native.server.listening, false);
        attempted++;
        native.route({
          method: candidate.method,
          url: candidate.path,
          handler() {
            effects++;
            return { unprotected: true };
          },
        });
      },
      close() {},
    };
    await assert.rejects(
      fixture(
        {
          ...settings(),
          ...(candidate.capabilitiesPath ? { capabilitiesPath: candidate.capabilitiesPath } : {}),
        },
        { plugins: [late] },
      ),
      collision,
    );
    assert.equal(attempted, 1, 'The conflicting plugin must run after dispatcher initialization');
    assert.equal(effects, 0);
    assert.equal(native?.server.listening, false);
  });

test('A distinct route registered by a later plugin coexists with authenticated tenant routes', async () => {
  let initialized = false;
  const late: Plugin = {
    id: 'late-independent-route',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['api', 'tenant-routing'],
    init(context) {
      context.require(TENANT_ROUTING_CAPABILITY);
      const api = context.require<ManagedApiServer>(COMPONENTS.api);
      assert.equal(api.native().server.listening, false);
      api.native().get('/api/late-health', async () => ({ ready: true }));
      initialized = true;
    },
    close() {},
  };
  const f = await fixture(settings(), { plugins: [late] });
  try {
    assert.equal(initialized, true);
    const health = await send(f.origin, '/api/late-health');
    assert.equal(health.status, 200, health.body);
    assert.deepEqual(health.json(), { ready: true });
    const routed = await send(f.origin, '/api/orders/id', {
      headers: { authorization: await f.token('north') },
    });
    assert.equal(routed.status, 200, routed.body);
    assert.equal(routed.json().tenant, 'north');
  } finally {
    await f.close();
  }
});
