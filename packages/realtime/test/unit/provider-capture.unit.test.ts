// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { realtimePlugin } from '../../dist/index.js';
import type { SseSource, SseEvent } from '../../dist/index.js';
import { fixture, sseRequest } from '../fixture.js';

const settings = (source: SseSource) => ({
  routes: [],
  websocketHandlers: {},
  sseSources: { events: source },
  policies: {},
  policy: { maxConcurrent: 1, timeoutMs: 1000 },
});

test('Realtime source capture never evaluates callable bind metadata at configuration time', () => {
  let effects = 0;
  const source: SseSource = {
    kind: 'pubsub',
    async *subscribe() {
      yield { id: 'tenant-a_1', type: 'update', data: 'original' };
    },
  };
  Object.defineProperty(source.subscribe, 'bind', {
    get() {
      effects++;
      throw new Error('Callable metadata must not execute');
    },
  });
  assert.doesNotThrow(() => realtimePlugin(settings(source)));
  assert.equal(effects, 0);
});

test('Authenticated native SSE retains original source and iterator receivers without callable metadata', async () => {
  let effects = 0,
    subscriptions = 0,
    cursors = 0,
    returned = 0;
  const guard = (callback: (...args: never[]) => unknown) => {
    for (const key of ['bind', 'name', 'length'])
      Object.defineProperty(callback, key, {
        configurable: true,
        get() {
          effects++;
          throw new Error('Callable metadata must not execute');
        },
      });
  };
  const source: SseSource = {
    kind: 'durable',
    async validateCursor(context) {
      assert.equal(this, source);
      assert.equal(context.tenant.tenantId, 'tenant-a');
      assert.equal(context.lastEventId, 'tenant-a_1');
      cursors++;
    },
    subscribe(context) {
      assert.equal(this, source);
      assert.equal(context.tenant.tenantId, 'tenant-a');
      subscriptions++;
      let sent = false;
      const iterator: AsyncIterableIterator<SseEvent> = {
        [Symbol.asyncIterator]() {
          assert.equal(this, iterator);
          return iterator;
        },
        async next() {
          assert.equal(this, iterator);
          if (sent) return { done: true, value: undefined };
          sent = true;
          return {
            done: false,
            value: { id: 'tenant-a_2', type: 'update', data: 'original tenant event' },
          };
        },
        async return() {
          assert.equal(this, iterator);
          returned++;
          return { done: true, value: undefined };
        },
      };
      for (const callback of [iterator[Symbol.asyncIterator], iterator.next, iterator.return!])
        guard(callback);
      return iterator;
    },
  };
  guard(source.subscribe);
  guard(source.validateCursor!);
  const f = await fixture({ sseSources: { events: source } });
  try {
    source.subscribe = () => {
      throw new Error('A late source replacement must not run');
    };
    source.validateCursor = async () => {
      throw new Error('A late cursor replacement must not run');
    };
    const result = await sseRequest(f.origin, {
      authorization: await f.token(),
      'last-event-id': 'tenant-a_1',
    });
    assert.equal(result.status, 200);
    assert.match(result.body, /id: tenant-a_2/);
    assert.match(result.body, /data: original tenant event/);
    assert.equal(cursors, 1);
    assert.equal(subscriptions, 1);
    assert.equal(returned, 1);
    assert.equal(effects, 0);
    const denied = await sseRequest(f.origin);
    assert.equal(denied.status, 401);
    assert.equal(subscriptions, 1);
  } finally {
    await f.close();
  }
});

test('Realtime rejects proxy source callbacks and prototypes without executing traps', () => {
  let traps = 0;
  const handler: ProxyHandler<object> = {
    get() {
      traps++;
      throw new Error('Proxy access must not run');
    },
    getOwnPropertyDescriptor() {
      traps++;
      throw new Error('Proxy inspection must not run');
    },
    getPrototypeOf() {
      traps++;
      throw new Error('Proxy traversal must not run');
    },
  };
  const source: SseSource = { kind: 'pubsub', async *subscribe() {} };
  for (const input of [
    new Proxy(source, handler),
    { ...source, subscribe: new Proxy(source.subscribe, handler) },
    Object.assign(Object.create(new Proxy({}, handler)), source),
  ])
    assert.throws(() => realtimePlugin(settings(input)), { code: 'EK_CONFIG_INVALID' });
  assert.equal(traps, 0);
});
