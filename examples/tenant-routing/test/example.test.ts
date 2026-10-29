// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './fixture.js';
import { initialRegistry, expandedRegistry, activate } from './registry.js';

test(
  'The public HTTPS example routes one quote API using signed tenants and denies frontend tenant selectors',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      snapshot = initialRegistry();
    await f.write(snapshot);
    assert.equal(JSON.parse((await f.validate()).stdout).valid, true);
    const app = await f.start(),
      body = { amount: 125 },
      a = await f.token(),
      b = await f.token('tenant-b');
    const local = await f.send(app.origin, '/api/quotes/calculate', {
      body,
      authorization: a,
      headers: { 'x-tenant-id': 'tenant-b' },
    });
    assert.deepEqual(local.json(), { quoteId: 'local-standard', total: 125 });
    const partner = await f.send(app.origin, '/api/quotes/calculate', {
      body,
      authorization: b,
      headers: { 'x-tenant-id': 'tenant-a', cookie: 'private=not-forwarded' },
    });
    assert.equal(local.status, 200, local.body);
    assert.equal(partner.status, 200, partner.body);
    assert.deepEqual(partner.json(), { quoteId: 'partner-one', total: 125 });
    assert.equal(f.calls.one, 1);
    assert.equal(f.calls.two, 0);
    for (const [authorization, status] of [
      [undefined, 401],
      ['Bearer forged', 401],
      [await f.token('tenant-a', 'unrelated'), 403],
      [await f.token('tenant-c'), 404],
    ] as const)
      assert.equal(
        (
          await f.send(app.origin, '/api/quotes/calculate', {
            body,
            ...(authorization ? { authorization } : {}),
          })
        ).status,
        status,
      );
    assert.equal(
      (
        await f.send(app.origin, '/api/quotes/calculate', {
          body: { amount: 'invalid' },
          authorization: a,
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await f.send(app.origin, '/api/quotes/calculate', {
          body: { amount: 125, tenant_id: 'tenant-b' },
          authorization: a,
        })
      ).status,
      400,
    );
    const capabilities = await f.send(app.origin, '/api/tenant/capabilities', { authorization: b });
    assert.equal(capabilities.headers['cache-control'], 'private, no-store');
    assert.deepEqual(capabilities.json().capabilities, [
      {
        operationId: 'quotes.calculate',
        method: 'POST',
        path: '/api/quotes/calculate',
        label: 'Calculate a quote',
      },
    ]);
    assert.doesNotMatch(capabilities.body, /partner|upstream|implementation|handler/);
    assert.deepEqual(
      (
        await f.send(app.origin, '/api/tenant/capabilities', {
          authorization: await f.token('tenant-c'),
        })
      ).json().capabilities,
      [],
    );
    assert.deepEqual((await f.send(app.origin, '/status')).json(), { ready: true });
    await assert.rejects(f.send(app.origin, '/status', { trust: false }));
    assert.doesNotMatch(app.logs(), /Bearer |private=not-forwarded/);
    await app.close();
    assert.ok(
      app.events.some(
        (event) => event.tenantId === 'tenant-b' && event.implementationId === 'quote-partner-one',
      ),
    );
  },
);

test(
  'A separately approved startup catalog can introduce a compatible existing upstream without application changes',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      original = expandedRegistry(initialRegistry()),
      updated = activate(
        {
          ...original,
          implementations: original.implementations.map((implementation) =>
            implementation.id === 'quote-partner-two' && implementation.kind === 'http'
              ? { ...implementation, upstreamKey: 'partner-added' }
              : implementation,
          ),
        },
        'catalog-addition',
        3,
      );
    await f.write(updated);
    assert.equal(JSON.parse((await f.validate()).stdout).valid, true);
    await assert.rejects(f.start(), /startup failed|exited before readiness/);
    const app = await f.start({
      approvedUpstreams: [...f.catalog, { ...f.catalog[1]!, key: 'partner-added' }],
    });
    const result = await f.send(app.origin, '/api/quotes/calculate', {
      authorization: await f.token('tenant-b'),
      body: { amount: 125 },
    });
    assert.equal(result.status, 200, result.body);
    assert.deepEqual(result.json(), { quoteId: 'partner-two', total: 125 });
    assert.equal(f.calls.one, 0);
    assert.equal(f.calls.two, 1);
  },
);

test(
  'Identical child binaries apply registry-only onboarding, implementation switch, new operation, rolling versions and higher-generation rollback',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      blue = initialRegistry(),
      green = expandedRegistry(blue),
      body = { amount: 125 };
    await f.write(blue);
    const old = await f.start(),
      b = await f.token('tenant-b'),
      c = await f.token('tenant-c');
    await f.write(green);
    assert.equal(JSON.parse((await f.validate()).stdout).activationGeneration, 2);
    const current = await f.start();
    assert.equal(old.revision, 'content-blue');
    assert.equal(current.revision, 'content-green');
    assert.equal(
      (await f.send(old.origin, '/api/quotes/calculate', { body, authorization: b })).json()
        .quoteId,
      'partner-one',
    );
    assert.equal(
      (await f.send(current.origin, '/api/quotes/calculate', { body, authorization: b })).json()
        .quoteId,
      'partner-two',
    );
    assert.equal(
      (await f.send(old.origin, '/api/quotes/calculate', { body, authorization: c })).status,
      404,
    );
    assert.equal(
      (await f.send(current.origin, '/api/quotes/calculate', { body, authorization: c })).json()
        .quoteId,
      'local-standard',
    );
    assert.equal(
      (await f.send(old.origin, '/api/orders/order-7/status', { authorization: c })).status,
      404,
    );
    assert.deepEqual(
      (await f.send(current.origin, '/api/orders/order-7/status', { authorization: c })).json(),
      { orderId: 'order-7', status: 'accepted' },
    );
    const oldCaps = (
        await f.send(old.origin, '/api/tenant/capabilities', { authorization: b })
      ).json(),
      newCaps = (
        await f.send(current.origin, '/api/tenant/capabilities', { authorization: c })
      ).json();
    assert.equal(oldCaps.revision, 'content-blue');
    assert.equal(newCaps.revision, 'content-green');
    assert.deepEqual(
      (newCaps.capabilities as { operationId: string }[]).map((entry) => entry.operationId),
      ['orders.status', 'quotes.calculate'],
    );
    await old.close();
    const restarted = await f.start();
    assert.equal(restarted.revision, 'content-green');
    await restarted.close();
    const rollbackSnapshot = activate(blue, blue.revision, 3);
    assert.equal(rollbackSnapshot.contentChecksum, blue.contentChecksum);
    await f.write(rollbackSnapshot);
    const rollback = await f.start();
    const reverted = (
      await f.send(rollback.origin, '/api/tenant/capabilities', { authorization: b })
    ).json();
    assert.equal(reverted.revision, 'content-blue');
    assert.equal(reverted.activationGeneration, 3);
    assert.equal(
      (await f.send(rollback.origin, '/api/quotes/calculate', { body, authorization: b })).json()
        .quoteId,
      'partner-one',
    );
    assert.equal(
      (await f.send(rollback.origin, '/api/quotes/calculate', { body, authorization: c })).status,
      404,
    );
    assert.equal(
      (await f.send(current.origin, '/api/tenant/capabilities', { authorization: b })).json()
        .revision,
      'content-green',
    );
  },
);

test(
  'Unknown deployed code and tampered checksums prevent child readiness without a fallback',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      blue = initialRegistry();
    const missing = activate(
      {
        ...blue,
        implementations: [
          ...blue.implementations,
          { id: 'not-installed', kind: 'handler', handlerKey: 'not-installed' },
        ],
      },
      'missing-code',
      2,
    );
    await f.write(missing);
    assert.equal(JSON.parse((await f.validate()).stdout).valid, true);
    await assert.rejects(f.start(), /startup failed|exited before readiness/);
    await f.write({ ...blue, contentChecksum: 'sha256:' + '0'.repeat(64) });
    await assert.rejects(f.validate());
    await assert.rejects(f.start(), /startup failed|exited before readiness/);
    await f.write(blue);
    const app = await f.start();
    assert.equal((await f.send(app.origin, '/status')).status, 200);
  },
);
