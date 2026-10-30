// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { fixture, send, settings } from '../http-fixture.js';

test('Public capability options reject executable metadata and invalid deadlines before authorization', async () => {
  let authorized = 0,
    hooks = 0;
  const f = await fixture({
    ...settings(),
    authorize() {
      authorized++;
      return true;
    },
  });
  try {
    const tenant = await f.tenant();
    const trap = () => {
      hooks++;
      throw new Error('Private capability option hook');
    };
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const candidates: unknown[] = [
      null,
      false,
      1,
      'options',
      [],
      ...[0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1000'].map((timeoutMs) => ({
        timeoutMs,
      })),
      Object.defineProperty({}, 'timeoutMs', { enumerable: true, get: trap }),
      Object.defineProperty({}, 'signal', { enumerable: true, get: trap }),
      Object.defineProperty({}, 'timeoutMs', { value: 1000 }),
      Object.create({ timeoutMs: 1000 }),
      { [Symbol('timeoutMs')]: 1000 },
      { extra: true },
      new Proxy({}, { get: trap, getPrototypeOf: trap, ownKeys: trap }),
      revoked.proxy,
      { signal: {} },
      { signal: { aborted: false, addEventListener: trap, removeEventListener: trap } },
      { signal: new Proxy(new AbortController().signal, { get: trap, getPrototypeOf: trap }) },
      { signal: Object.defineProperty(new AbortController().signal, 'aborted', { get: trap }) },
    ];
    for (const input of candidates)
      await assert.rejects(
        f.service.capabilities.list(tenant, input as OperationOptions),
        (error: unknown) => error instanceof KitError,
      );
    await assert.rejects(f.service.capabilities.list(tenant, { signal: AbortSignal.abort() }), {
      code: 'EK_ABORTED',
    });
    assert.equal(authorized, 0);
    assert.equal(hooks, 0);
    const options = Object.assign(Object.create(null), {
      timeoutMs: 1000,
      signal: new AbortController().signal,
    }) as OperationOptions;
    assert.equal((await f.service.capabilities.list(tenant, options)).capabilities.length, 2);
    assert.equal(authorized, 2);
    assert.equal((await f.service.capabilities.list(tenant)).capabilities.length, 2);
    assert.equal(authorized, 4);
    assert.doesNotMatch(f.logs(), /Private capability option hook/);
  } finally {
    await f.close();
  }
});

for (const failure of ['abort', 'deadline'] as const)
  test(
    `Public capability ${failure} rejects partial discovery while retaining late authorization through physical shutdown`,
    { timeout: 10000 },
    async () => {
      let enter!: () => void,
        release!: () => void,
        effects = 0;
      const entered = new Promise<void>((resolve) => {
          enter = resolve;
        }),
        gate = new Promise<void>((resolve) => {
          release = resolve;
        });
      const calls: { tenant: string; operation: string }[] = [];
      const base = settings();
      const f = await fixture({
        ...base,
        async authorize({ tenant, operationId }) {
          calls.push({ tenant: tenant.tenantId, operation: operationId });
          if (tenant.tenantId === 'north' && operationId === 'orders.read') {
            enter();
            await gate;
          }
          return true;
        },
        handlers: Object.fromEntries(
          Object.entries(base.handlers).map(([name, handler]) => [
            name,
            (context: Parameters<typeof handler>[0]) => {
              effects++;
              return handler(context);
            },
          ]),
        ),
      });
      let published = false,
        stopped = false;
      const controller = new AbortController();
      try {
        const tenant = await f.tenant('north');
        const pending = f.service.capabilities.list(tenant, {
          signal: controller.signal,
          timeoutMs: failure === 'deadline' ? 150 : 2000,
        });
        void pending.then(
          () => {
            published = true;
          },
          () => {},
        );
        await within(() => entered, { timeoutMs: 2000 });
        // Another authenticated tenant continues on the actual HTTP listener while this callback waits.
        const other = await send(f.origin, '/api/tenant/capabilities', {
          headers: { authorization: await f.token('south') },
        });
        assert.equal(other.status, 200, other.body);
        assert.equal((other.json().capabilities as unknown[]).length, 2);
        if (failure === 'abort') controller.abort();
        await assert.rejects(pending, { code: failure === 'abort' ? 'EK_ABORTED' : 'EK_TIMEOUT' });
        assert.equal(published, false);
        assert.deepEqual(
          calls.filter((call) => call.tenant === 'north').map((call) => call.operation),
          ['orders.create', 'orders.read'],
        );
        const healthy = await f.service.capabilities.list(await f.tenant('south'));
        assert.deepEqual(
          healthy.capabilities.map((value) => value.operationId),
          ['orders.create', 'orders.read'],
        );
        const stopping = f.app.stop({ timeoutMs: 3000 });
        void stopping.then(
          () => {
            stopped = true;
          },
          () => {},
        );
        await nextTurn();
        assert.equal(f.app.state, 'DRAINING');
        assert.equal(
          stopped,
          false,
          'Logical cancellation must not hide the still-running authorization callback',
        );
        await assert.rejects(f.service.capabilities.list(tenant), { code: 'EK_LIFECYCLE_STATE' });
        release();
        await stopping;
        assert.equal(stopped, true);
        assert.equal(f.app.state, 'CLOSED');
        assert.equal(published, false);
        assert.equal(effects, 0);
        assert.deepEqual(
          calls.filter((call) => call.tenant === 'north').map((call) => call.operation),
          ['orders.create', 'orders.read'],
        );
        await assert.rejects(f.service.capabilities.list(tenant), { code: 'EK_RESOURCE_CLOSED' });
      } finally {
        release();
        await f.close();
      }
    },
  );
