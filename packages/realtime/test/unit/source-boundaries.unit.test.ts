// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'node:http';
import type { SseEvent } from '../../dist/index.js';
import { fixture, sseRequest } from '../fixture.js';

/** Observe native termination after committed SSE headers without interpreting it as a JSON error. */
function observeTermination(origin: string, authorization: string) {
  return new Promise<string>((resolve) => {
    let body = '';
    const request = get(
      origin + '/events',
      {
        headers: { authorization, accept: 'text/event-stream' },
        signal: AbortSignal.timeout(3000),
      },
      (response) => {
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          body += chunk;
        });
        response.once('end', () => resolve(body));
        response.once('error', () => resolve(body));
      },
    );
    request.once('error', () => resolve(body));
  });
}

test(
  'A failed actual SSE source read releases confirmed cleanup, hides provider diagnostics and permits a later healthy stream',
  { timeout: 5000 },
  async () => {
    let subscriptions = 0,
      returned = 0,
      finish!: () => void;
    const retired = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const f = await fixture({
      sseSources: {
        events: {
          kind: 'pubsub',
          subscribe(context) {
            const failed = ++subscriptions === 1;
            let sent = false;
            const iterator: AsyncIterableIterator<SseEvent> = {
              [Symbol.asyncIterator]() {
                return this;
              },
              async next() {
                if (failed)
                  throw new Error('Private source backend endpoint and credential detail');
                if (sent) return { done: true, value: undefined };
                sent = true;
                return { done: false, value: { id: 'owned_1', type: 'update', data: 'healthy' } };
              },
              async return() {
                assert.equal(context.signal.aborted, true);
                returned++;
                if (failed) finish();
                return { done: true, value: undefined };
              },
            };
            return iterator;
          },
        },
      },
    });
    try {
      const authorization = await f.token(),
        firstBody = await observeTermination(f.origin, authorization);
      // Already committed empty SSE responses may end normally or terminate at transport level.
      assert.equal(firstBody, '');
      await retired;
      const healthy = await sseRequest(f.origin, { authorization });
      assert.equal(healthy.status, 200);
      assert.match(healthy.body, /data: healthy/);
      assert.equal(subscriptions, 2);
      await f.service.close();
      assert.equal(returned, 2);
      assert.doesNotMatch(f.logs(), /Private source backend|credential detail/);
    } finally {
      await f.close();
    }
  },
);

test(
  'An actual SSE event exceeding the complete framing budget emits no partial event and retires its generator',
  { timeout: 5000 },
  async () => {
    let subscriptions = 0,
      returned = 0,
      finish!: () => void;
    const retired = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const f = await fixture({
      policy: { maxConcurrent: 8, timeoutMs: 1000, maxOutputBytes: 64 },
      sseSources: {
        events: {
          kind: 'pubsub',
          async *subscribe() {
            const oversized = ++subscriptions === 1;
            try {
              yield {
                id: oversized ? 'owned_' + 'x'.repeat(200) : 'owned_1',
                type: 'update',
                data: oversized ? 'private-overflow-event' : 'healthy',
              };
            } finally {
              returned++;
              if (oversized) finish();
            }
          },
        },
      },
    });
    try {
      const authorization = await f.token(),
        firstBody = await observeTermination(f.origin, authorization);
      assert.equal(firstBody, '');
      await retired;
      const healthy = await sseRequest(f.origin, { authorization });
      assert.equal(healthy.status, 200);
      assert.match(healthy.body, /data: healthy/);
      await f.service.close();
      assert.equal(returned, 2);
      assert.equal(subscriptions, 2);
      assert.doesNotMatch(f.logs(), /private-overflow-event|owned_x{20}/);
    } finally {
      await f.close();
    }
  },
);

test(
  'A durable source without a cursor validator rejects resume before subscribing and supports finite natural exhaustion',
  { timeout: 5000 },
  async () => {
    let subscriptions = 0,
      reads = 0;
    const f = await fixture({
      sseSources: {
        events: {
          kind: 'durable',
          subscribe() {
            subscriptions++;
            let sent = false;
            return {
              [Symbol.asyncIterator]() {
                return {
                  async next(): Promise<IteratorResult<SseEvent>> {
                    reads++;
                    if (sent) return { done: true, value: undefined };
                    sent = true;
                    return {
                      done: false,
                      value: { id: 'owned_1', type: 'update', data: 'finite' },
                    };
                  },
                };
              },
            };
          },
        },
      },
    });
    try {
      const authorization = await f.token();
      const denied = await sseRequest(f.origin, { authorization, 'last-event-id': 'owned_1' });
      assert.equal(denied.status, 409);
      assert.equal(subscriptions, 0);
      assert.equal(reads, 0);
      const accepted = await sseRequest(f.origin, { authorization });
      assert.equal(accepted.status, 200);
      assert.equal(accepted.body, 'id: owned_1\nevent: update\ndata: finite\n\n');
      assert.equal(subscriptions, 1);
      assert.equal(reads, 2);
      await assert.doesNotReject(f.service.close());
    } finally {
      await f.close();
    }
  },
);
