// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
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
  for (let attempt = 0; attempt < 200 && !check(); attempt++) await delay(5);
  assert.ok(check(), 'The physical loader lifecycle did not settle');
}

async function runtime(maxOperationMs: number) {
  const entered = deferred(),
    gate = deferred(),
    parent = Object.freeze({ id: 1 }),
    calls: string[] = [],
    reads: string[] = [],
    authorized: string[] = [];
  let held = true,
    pending = 0,
    signal: AbortSignal | undefined;
  const tls = await tlsFiles();
  const f = await fixture(
    {
      schema:
        'type Record { secret: String! } type Item { record: Record } type Query { item: Item! ping: String! }',
      resolvers: { Query: { item: () => parent, ping: () => 'pong' } },
      loaders: {
        Item: {
          record: {
            async load(requests, context) {
              const tenant = context.auth!.tenantId;
              calls.push(tenant);
              assert.ok(requests.every((item) => item.parent === parent));
              if (held && tenant === 'tenant-a') {
                pending++;
                signal = context.signal;
                entered.resolve();
                // The application loader intentionally retains physical backend work after cancellation.
                try {
                  await gate.promise;
                } finally {
                  pending--;
                }
              }
              return requests.map(() => ({
                get secret() {
                  reads.push(tenant);
                  return tenant + '-private-loader-result';
                },
              }));
            },
          },
        },
      },
      security: {
        limits: { maxOperationMs },
        authorizeField({ context, field }) {
          assert.ok(context.auth);
          if (field.parentType === 'Record') authorized.push(context.auth.tenantId);
          return true;
        },
      },
    },
    { tls: tls.tls },
  ).catch(async (error: unknown) => {
    await tls.close();
    throw error;
  });
  const query = { query: '{ item { record { secret } } }' };
  return {
    f,
    tls,
    query,
    entered,
    gate,
    calls,
    reads,
    authorized,
    pending: () => pending,
    signal: () => signal,
    async assertIsolatedAndRecover() {
      assert.equal(pending, 1);
      assert.equal(f.service.stats().activeOperations, 1);
      assert.deepEqual(calls, ['tenant-a']);
      assert.deepEqual(reads, []);
      assert.deepEqual(authorized, []);
      const other = await send(f.origin, query, {
        headers: { authorization: await f.token('tenant-b'), 'x-tenant-id': 'tenant-a' },
        ca: tls.ca,
      });
      assert.deepEqual(other.json(), {
        data: { item: { record: { secret: 'tenant-b-private-loader-result' } } },
      });
      assert.deepEqual(calls, ['tenant-a', 'tenant-b']);
      assert.deepEqual(reads, ['tenant-b']);
      assert.deepEqual(authorized, ['tenant-b']);
      assert.equal(f.service.stats().activeOperations, 1);
      assert.equal(pending, 1);
      gate.resolve();
      await until(() => pending === 0 && f.service.stats().activeOperations === 0);
      assert.deepEqual(reads, ['tenant-b']);
      assert.deepEqual(authorized, ['tenant-b']);
      held = false;
      const recovered = await send(f.origin, query, {
        headers: { authorization: await f.token() },
        ca: tls.ca,
      });
      assert.deepEqual(recovered.json(), {
        data: { item: { record: { secret: 'tenant-a-private-loader-result' } } },
      });
      assert.deepEqual(calls, ['tenant-a', 'tenant-b', 'tenant-a']);
      assert.deepEqual(reads, ['tenant-b', 'tenant-a']);
      assert.deepEqual(authorized, ['tenant-b', 'tenant-a']);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(f.service.stats().loaderBatches, 3);
    },
    async close() {
      gate.resolve();
      try {
        await f.close();
      } finally {
        await tls.close();
      }
    },
  };
}

test(
  'Public HTTPS loader deadlines retain physical batches and suppress late result getters while another verified tenant proceeds',
  { timeout: 15000 },
  async () => {
    const r = await runtime(1000);
    let response: ReturnType<typeof send> | undefined;
    try {
      response = send(r.f.origin, r.query, {
        headers: { authorization: await r.f.token() },
        ca: r.tls.ca,
      });
      await r.entered.promise;
      const result = await response;
      assert.equal(result.status, 504, result.body);
      assert.match(result.body, /EK_GQL_TIMEOUT/);
      assert.doesNotMatch(result.body + r.f.logs(), /private-loader-result|Bearer /);
      assert.equal(r.signal()?.aborted, true);
      await r.assertIsolatedAndRecover();
    } finally {
      r.gate.resolve();
      await Promise.allSettled(response ? [response] : []);
      await r.close();
    }
  },
);

test(
  'A public HTTPS client abort cannot retire pending loader work or expose its late cached result to another tenant',
  { timeout: 15000 },
  async () => {
    const r = await runtime(5000),
      cancelled = new AbortController();
    let outgoing: ReturnType<typeof request> | undefined;
    try {
      const authorization = await r.f.token();
      const response = new Promise<number>((resolve, reject) => {
        outgoing = request(
          r.f.origin + '/graphql',
          {
            method: 'POST',
            ca: r.tls.ca,
            signal: cancelled.signal,
            headers: { authorization, 'content-type': 'application/json' },
          },
          (incoming) => {
            incoming.resume();
            incoming.once('error', reject);
            incoming.once('end', () => resolve(incoming.statusCode!));
          },
        );
        outgoing.once('error', reject);
        outgoing.end(JSON.stringify(r.query));
      });
      void response.catch(() => undefined);
      await r.entered.promise;
      cancelled.abort();
      await assert.rejects(response, { name: 'AbortError' });
      await until(() => r.signal()?.aborted === true);
      await r.assertIsolatedAndRecover();
    } finally {
      cancelled.abort();
      outgoing?.destroy();
      await r.close();
    }
  },
);
