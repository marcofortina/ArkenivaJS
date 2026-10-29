// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tenantRoutingPlugin } from '../../dist/index.js';
import { fixture, settings, registry, send } from '../http-fixture.js';

test('Tenant registry capture ignores executable callable metadata before loading', () => {
  let effects = 0;
  const input = settings();
  Object.defineProperty(input.registry.loadSnapshot, 'bind', {
    get() {
      effects++;
      throw new Error('Registry callable metadata must not execute');
    },
  });
  assert.doesNotThrow(() => tenantRoutingPlugin(input));
  assert.equal(effects, 0);
});

test('Native authenticated routing retains the original registry method and receiver after late replacement', async () => {
  let effects = 0,
    loads = 0;
  const snapshot = registry();
  const provider = {
    async loadSnapshot() {
      assert.equal(this, provider);
      loads++;
      return snapshot;
    },
  };
  for (const key of ['bind', 'name', 'length'])
    Object.defineProperty(provider.loadSnapshot, key, {
      get() {
        effects++;
        throw new Error('Registry callable metadata must not execute');
      },
    });
  const f = await fixture({ ...settings(snapshot), registry: provider });
  try {
    provider.loadSnapshot = async () => {
      throw new Error('The late registry replacement must not run');
    };
    for (const tenant of ['north', 'south']) {
      const result = await send(f.origin, '/api/orders/item-1', {
        headers: {
          authorization: await f.token(tenant),
          'x-tenant-id': tenant === 'north' ? 'south' : 'north',
        },
      });
      assert.equal(result.status, 200, result.body);
      assert.equal(result.json().tenant, tenant);
      assert.equal(result.json().implementation, tenant);
    }
    assert.equal((await send(f.origin, '/api/orders/item-1')).status, 401);
    assert.equal(loads, 1);
    assert.equal(effects, 0);
  } finally {
    await f.close();
  }
});

test('Tenant registry rejects proxied callbacks and prototype inspection without traps', () => {
  let effects = 0;
  const fail = () => {
    effects++;
    throw new Error('Proxy inspection must not execute');
  };
  const handler: ProxyHandler<object> = {
    get: fail,
    getOwnPropertyDescriptor: fail,
    getPrototypeOf: fail,
  };
  const input = settings();
  for (const provider of [
    new Proxy(input.registry, handler),
    { loadSnapshot: new Proxy(input.registry.loadSnapshot, handler) },
    Object.create(new Proxy(input.registry, handler)),
  ])
    assert.throws(() => tenantRoutingPlugin({ ...input, registry: provider }), {
      code: 'EK_TROUTE_CONFIG',
    });
  assert.equal(effects, 0);
});
