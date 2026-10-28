// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import type { GraphqlRequestContext } from '../../dist/index.js';
import { fixture, send } from '../fixture.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test(
  'GraphQL physical admission caps 128 concurrent operations and recovers only after real work settles',
  { timeout: 15000 },
  async () => {
    const gate = deferred(),
      full = deferred();
    let started = 0;
    const f = await fixture({
      schema: 'type Query { delayed: Boolean! ping: String! }',
      resolvers: {
        Query: {
          ping: () => 'pong',
          delayed: async () => {
            if (++started === 128) full.resolve();
            await gate.promise;
            return true;
          },
        },
      },
      security: { authorizeField: () => true, limits: { maxOperationMs: 60000 } },
    });
    const pending: ReturnType<typeof send>[] = [];
    try {
      const authorization = await f.token();
      assert.equal(
        (await send(f.origin, { query: '{ ping }' }, { headers: { authorization } })).status,
        200,
      );
      for (let i = 0; i < 128; i++)
        pending.push(send(f.origin, { query: '{ delayed }' }, { headers: { authorization } }));
      await full.promise;
      assert.equal(f.service.stats().activeOperations, 128);
      const denied = await send(f.origin, { query: '{ delayed }' }, { headers: { authorization } });
      assert.equal(denied.status, 500, denied.body);
      assert.match(denied.body, /EK_GQL_EXECUTION/);
      assert.equal(started, 128);
      assert.equal(f.service.stats().activeOperations, 128);
      gate.resolve();
      const results = await Promise.all(pending);
      assert.ok(
        results.every(
          (result) => result.status === 200 && result.body === '{"data":{"delayed":true}}',
        ),
      );
      assert.equal(f.service.stats().activeOperations, 0);
      const next = await send(f.origin, { query: '{ delayed }' }, { headers: { authorization } });
      assert.equal(next.status, 200, next.body);
      assert.equal(started, 129);
    } finally {
      gate.resolve();
      await Promise.allSettled(pending);
      await f.close();
    }
  },
);

test(
  'Forced shutdown aborts cooperative query and mutation resolvers and releases the listener',
  { timeout: 15000 },
  async () => {
    for (const kind of ['query', 'mutation'] as const) {
      const entered = deferred(),
        aborted = deferred();
      let signal: AbortSignal | undefined;
      const execute = async (
        _parent: unknown,
        _args: Readonly<Record<string, unknown>>,
        context: GraphqlRequestContext,
      ) => {
        signal = context.signal;
        entered.resolve();
        await new Promise<void>((resolve) =>
          context.signal.addEventListener(
            'abort',
            () => {
              aborted.resolve();
              resolve();
            },
            { once: true },
          ),
        );
        return null;
      };
      const f = await fixture({
        schema: 'type Query { delayed: Boolean } type Mutation { delayed: Boolean }',
        resolvers: { Query: { delayed: execute }, Mutation: { delayed: execute } },
        security: { authorizeField: () => true },
      });
      const native = f.api.native();
      try {
        const pending = send(
          f.origin,
          { query: `${kind} { delayed }` },
          { headers: { authorization: await f.token() } },
        ).then(
          (value) => value,
          (error: unknown) => error,
        );
        await entered.promise;
        const stopping = f.app.stop({ timeoutMs: 100 });
        await assert.rejects(stopping, { code: 'EK_TIMEOUT' });
        await aborted.promise;
        assert.equal(signal?.aborted, true);
        await pending;
        for (let i = 0; i < 100 && f.service.stats().activeOperations; i++) await setImmediate();
        assert.equal(f.service.stats().activeOperations, 0);
        assert.equal(native.server.listening, false);
        assert.equal(f.app.state, 'CLOSED');
        await f.app.stop();
      } finally {
        await f.api.close().catch(() => undefined);
        await f.close();
      }
    }
  },
);

test(
  'Forced shutdown retains ownership of uncooperative admitted mutation work without claiming rollback',
  { timeout: 15000 },
  async () => {
    const entered = deferred(),
      release = deferred();
    let effects = 0,
      signal: AbortSignal | undefined;
    const f = await fixture({
      schema: 'type Query { ping: String! } type Mutation { update: Boolean! }',
      resolvers: {
        Query: { ping: () => 'pong' },
        Mutation: {
          update: async (_parent, _args, context) => {
            signal = context.signal;
            entered.resolve();
            await release.promise;
            effects++;
            return true;
          },
        },
      },
      security: { authorizeField: () => true },
    });
    const native = f.api.native();
    try {
      const pending = send(
        f.origin,
        { query: 'mutation { update }' },
        { headers: { authorization: await f.token() } },
      ).then(
        (value) => value,
        (error: unknown) => error,
      );
      await entered.promise;
      await assert.rejects(f.app.stop({ timeoutMs: 100 }), { code: 'EK_TIMEOUT' });
      assert.equal(signal?.aborted, true);
      // Fastify begins native listener closure on the following event-loop turn.
      await setImmediate();
      assert.equal(native.server.listening, false);
      assert.equal(effects, 0);
      assert.equal(f.service.stats().activeOperations, 1);
      release.resolve();
      await pending;
      for (let i = 0; i < 100 && f.service.stats().activeOperations; i++) await setImmediate();
      assert.equal(effects, 1);
      assert.equal(f.service.stats().activeOperations, 0);
    } finally {
      release.resolve();
      await f.api.close().catch(() => undefined);
      await f.close();
    }
  },
);
