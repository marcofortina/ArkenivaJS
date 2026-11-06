// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, send, tlsFiles } from '../fixture.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function until(check: () => boolean) {
  for (let attempt = 0; attempt < 300 && !check(); attempt++) await delay(5);
  assert.ok(check(), 'The application collection did not retire its physical work');
}

test(
  'Public HTTPS list deadlines retain pending elements and close their iterator before late values can reach child fields',
  { timeout: 15000 },
  async () => {
    const entered = deferred(),
      gate = deferred(),
      tls = await tlsFiles(),
      acquisitions: string[] = [],
      retirements: string[] = [],
      getters: string[] = [];
    let held = true,
      pending = 0,
      signal: AbortSignal | undefined;
    const f = await fixture(
      {
        schema: 'type Item { label: String! } type Query { items(first: Int!): [Item!]! }',
        resolvers: {
          Query: {
            items(_parent, _args, context) {
              const tenant = context.auth!.tenantId;
              acquisitions.push(tenant);
              return (function* () {
                try {
                  const item = {
                    get label() {
                      getters.push(tenant);
                      return tenant + '-private-collection-value';
                    },
                  };
                  if (held && tenant === 'tenant-a') {
                    signal = context.signal;
                    pending++;
                    entered.resolve();
                    // The application's element provider retains work until its own backend settles.
                    yield gate.promise.then(() => {
                      pending--;
                      return item;
                    });
                  } else yield item;
                } finally {
                  retirements.push(tenant);
                }
              })();
            },
          },
        },
        security: { authorizeField: () => true, limits: { maxOperationMs: 1000 } },
      },
      { tls: tls.tls },
    ).catch(async (error: unknown) => {
      await tls.close();
      throw error;
    });
    const query = { query: '{ items(first: 1) { label } }' };
    let response: ReturnType<typeof send> | undefined;
    try {
      response = send(f.origin, query, {
        headers: { authorization: await f.token('tenant-a') },
        ca: tls.ca,
      });
      await entered.promise;
      const expired = await response;
      assert.equal(expired.status, 504, expired.body);
      assert.match(expired.body, /EK_GQL_TIMEOUT/);
      assert.equal(signal?.aborted, true);
      assert.equal(pending, 1);
      assert.equal(f.service.stats().activeOperations, 1);
      assert.deepEqual(retirements, []);
      assert.deepEqual(getters, []);
      const other = await send(f.origin, query, {
        headers: { authorization: await f.token('tenant-b'), 'x-tenant-id': 'tenant-a' },
        ca: tls.ca,
      });
      assert.deepEqual(other.json(), {
        data: { items: [{ label: 'tenant-b-private-collection-value' }] },
      });
      assert.deepEqual(acquisitions, ['tenant-a', 'tenant-b']);
      assert.deepEqual(retirements, ['tenant-b']);
      assert.deepEqual(getters, ['tenant-b']);
      assert.equal(pending, 1);
      assert.equal(f.service.stats().activeOperations, 1);
      gate.resolve();
      await until(() => pending === 0 && f.service.stats().activeOperations === 0);
      assert.deepEqual(retirements, ['tenant-b', 'tenant-a']);
      assert.deepEqual(getters, ['tenant-b']);
      held = false;
      const recovered = await send(f.origin, query, {
        headers: { authorization: await f.token('tenant-a') },
        ca: tls.ca,
      });
      assert.deepEqual(recovered.json(), {
        data: { items: [{ label: 'tenant-a-private-collection-value' }] },
      });
      assert.deepEqual(acquisitions, ['tenant-a', 'tenant-b', 'tenant-a']);
      assert.deepEqual(retirements, ['tenant-b', 'tenant-a', 'tenant-a']);
      assert.deepEqual(getters, ['tenant-b', 'tenant-a']);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.doesNotMatch(expired.body + f.logs(), /private-collection-value|Bearer /);
    } finally {
      gate.resolve();
      await Promise.allSettled(response ? [response] : []);
      try {
        await f.close();
      } finally {
        await tls.close();
      }
    }
  },
);

test('An oversized application iterable closes before child effects and preserves the full bound on recovery', async () => {
  let size = 3,
    yielded = 0,
    retired = 0,
    getters = 0;
  const f = await fixture({
    schema: 'type Item { label: String! } type Query { items(first: Int!): [Item!]! }',
    resolvers: {
      Query: {
        items() {
          return (function* () {
            try {
              for (let index = 0; index < size; index++) {
                yielded++;
                yield {
                  get label() {
                    getters++;
                    return 'owned-item-' + index;
                  },
                };
              }
            } finally {
              retired++;
            }
          })();
        },
      },
    },
    security: { authorizeField: () => true, limits: { maxCollectionItems: 2 } },
  });
  try {
    const headers = { authorization: await f.token() },
      query = { query: '{ items(first: 2) { label } }' },
      excessive = await send(f.origin, query, { headers });
    assert.equal(excessive.status, 200, excessive.body);
    assert.equal(excessive.json().data, null);
    assert.match(excessive.body, /EK_GQL_COMPLEXITY/);
    assert.doesNotMatch(excessive.body, /owned-item/);
    assert.equal(yielded, 3);
    assert.equal(retired, 1);
    assert.equal(getters, 0);
    size = 2;
    const recovered = await send(f.origin, query, { headers });
    assert.deepEqual(recovered.json(), {
      data: { items: [{ label: 'owned-item-0' }, { label: 'owned-item-1' }] },
    });
    assert.equal(yielded, 5);
    assert.equal(retired, 2);
    assert.equal(getters, 2);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(f.logs(), /owned-item|Bearer /);
  } finally {
    await f.close();
  }
});
