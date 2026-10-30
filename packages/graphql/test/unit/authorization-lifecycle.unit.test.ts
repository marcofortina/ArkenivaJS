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
  assert.ok(check(), 'The authorization callback did not reach its physical lifecycle state');
}

test(
  'HTTPS query and mutation deadlines retain stalled authorization until late approval settles without field effects',
  { timeout: 15000 },
  async () => {
    const entered = deferred(),
      gate = deferred();
    let held = true,
      started = 0,
      pending = 0,
      roots = 0,
      mutations = 0,
      getters = 0;
    const signals: AbortSignal[] = [];
    const tls = await tlsFiles();
    const f = await fixture(
      {
        schema:
          'type Item { secret: String! } type Query { item: Item! ping: String! } type Mutation { update: Boolean! }',
        resolvers: {
          Query: {
            ping: () => 'pong',
            item: () => {
              roots++;
              return {
                get secret() {
                  getters++;
                  return 'authorized-only-value';
                },
              };
            },
          },
          Mutation: {
            update: () => {
              mutations++;
              return true;
            },
          },
        },
        security: {
          limits: { maxOperationMs: 1000 },
          async authorizeField({ context, field }) {
            if (
              held &&
              context.auth?.tenantId === 'tenant-a' &&
              ((field.parentType === 'Query' && field.fieldName === 'item') ||
                field.parentType === 'Mutation')
            ) {
              pending++;
              signals.push(context.signal);
              if (++started === 2) entered.resolve();
              // This application policy deliberately ignores cancellation until its own backend settles.
              try {
                await gate.promise;
              } finally {
                pending--;
              }
            }
            return true;
          },
        },
      },
      { tls: tls.tls },
    ).catch(async (error: unknown) => {
      await tls.close();
      throw error;
    });
    const requests: ReturnType<typeof send>[] = [];
    try {
      const headers = { authorization: await f.token() };
      requests.push(send(f.origin, { query: '{ item { secret } }' }, { headers, ca: tls.ca }));
      requests.push(send(f.origin, { query: 'mutation { update }' }, { headers, ca: tls.ca }));
      await entered.promise;
      const responses = await Promise.all(requests);
      for (const response of responses) {
        assert.equal(response.status, 504, response.body);
        assert.match(response.body, /EK_GQL_TIMEOUT/);
        assert.doesNotMatch(response.body, /authorized-only-value|Bearer /);
      }
      assert.equal(started, 2);
      assert.equal(pending, 2);
      assert.ok(signals.every((signal) => signal.aborted));
      assert.equal(f.service.stats().activeOperations, 2);
      assert.deepEqual({ roots, mutations, getters }, { roots: 0, mutations: 0, getters: 0 });
      const healthy = await send(
        f.origin,
        { query: '{ ping }' },
        { headers: { authorization: await f.token('tenant-b') }, ca: tls.ca },
      );
      assert.deepEqual(healthy.json(), { data: { ping: 'pong' } });
      assert.equal(f.service.stats().activeOperations, 2);
      gate.resolve();
      await until(() => pending === 0 && f.service.stats().activeOperations === 0);
      assert.equal(started, 2);
      assert.deepEqual({ roots, mutations, getters }, { roots: 0, mutations: 0, getters: 0 });
      held = false;
      const query = await send(f.origin, { query: '{ item { secret } }' }, { headers, ca: tls.ca });
      assert.deepEqual(query.json(), { data: { item: { secret: 'authorized-only-value' } } });
      const mutation = await send(
        f.origin,
        { query: 'mutation { update }' },
        { headers, ca: tls.ca },
      );
      assert.deepEqual(mutation.json(), { data: { update: true } });
      assert.deepEqual({ roots, mutations, getters }, { roots: 1, mutations: 1, getters: 1 });
      assert.equal(f.service.stats().activeOperations, 0);
    } finally {
      gate.resolve();
      await Promise.allSettled(requests);
      await f.close();
      await tls.close();
    }
  },
);

test(
  'A real HTTPS client abort cannot release a pending field-policy reservation or execute its late approved mutation',
  { timeout: 15000 },
  async () => {
    const entered = deferred(),
      gate = deferred();
    let held = true,
      started = 0,
      pending = 0,
      mutations = 0;
    let signal: AbortSignal | undefined;
    const tls = await tlsFiles();
    const f = await fixture(
      {
        schema: 'type Query { ping: String! } type Mutation { update: Boolean! }',
        resolvers: {
          Query: { ping: () => 'pong' },
          Mutation: {
            update: () => {
              mutations++;
              return true;
            },
          },
        },
        security: {
          limits: { maxOperationMs: 5000 },
          async authorizeField({ context, field }) {
            if (held && context.auth?.tenantId === 'tenant-a' && field.operation === 'mutation') {
              started++;
              pending++;
              signal = context.signal;
              entered.resolve();
              try {
                await gate.promise;
              } finally {
                pending--;
              }
            }
            return true;
          },
        },
      },
      { tls: tls.tls },
    ).catch(async (error: unknown) => {
      await tls.close();
      throw error;
    });
    const cancelled = new AbortController();
    let outgoing: ReturnType<typeof request> | undefined;
    try {
      const authorization = await f.token();
      const response = new Promise<number>((resolve, reject) => {
        outgoing = request(
          f.origin + '/graphql',
          {
            method: 'POST',
            ca: tls.ca,
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
        outgoing.end(JSON.stringify({ query: 'mutation { update }' }));
      });
      void response.catch(() => undefined);
      await entered.promise;
      cancelled.abort();
      await assert.rejects(response, { name: 'AbortError' });
      await until(() => signal?.aborted === true);
      assert.equal(started, 1);
      assert.equal(pending, 1);
      assert.equal(mutations, 0);
      assert.equal(f.service.stats().activeOperations, 1);
      const healthy = await send(
        f.origin,
        { query: '{ ping }' },
        { headers: { authorization: await f.token('tenant-b') }, ca: tls.ca },
      );
      assert.deepEqual(healthy.json(), { data: { ping: 'pong' } });
      assert.equal(f.service.stats().activeOperations, 1);
      gate.resolve();
      await until(() => pending === 0 && f.service.stats().activeOperations === 0);
      assert.equal(mutations, 0);
      assert.equal(started, 1);
      held = false;
      const recovered = await send(
        f.origin,
        { query: 'mutation { update }' },
        { headers: { authorization }, ca: tls.ca },
      );
      assert.deepEqual(recovered.json(), { data: { update: true } });
      assert.equal(mutations, 1);
      assert.equal(f.service.stats().activeOperations, 0);
    } finally {
      cancelled.abort();
      outgoing?.destroy();
      gate.resolve();
      await f.close();
      await tls.close();
    }
  },
);
