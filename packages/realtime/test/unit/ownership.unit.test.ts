// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { get } from 'node:http';
import { setImmediate } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { MessageBus, Plugin } from '@arkenivajs/core';
import type { SseEvent } from '../../dist/index.js';
import { fixture, sseRequest } from '../fixture.js';

for (const mode of [
  'throw',
  'reject',
  'late-reject',
  'incomplete',
  'malformed',
  'accessor',
  'proxy',
  'inherited',
])
  test(
    `An SSE iterator return ${mode} remains visible after the disconnected connection has retired`,
    { timeout: 10000 },
    async () => {
      let returned!: () => void,
        rejectCleanup = () => {},
        allocations = 0,
        completionReads = 0;
      const cleanup = new Promise<void>((resolve) => {
        returned = resolve;
      });
      const f = await fixture({
        sseSources: {
          events: {
            kind: 'pubsub',
            subscribe(context) {
              allocations++;
              let sent = false;
              const iterator: AsyncIterableIterator<SseEvent> = {
                [Symbol.asyncIterator]() {
                  return this;
                },
                async next() {
                  if (!sent) {
                    sent = true;
                    return {
                      done: false as const,
                      value: { id: 'owned_1', type: 'update', data: 'owned event' },
                    };
                  }
                  if (!context.signal.aborted)
                    await new Promise<void>((resolve) =>
                      context.signal.addEventListener('abort', () => resolve(), { once: true }),
                    );
                  return { done: true as const, value: undefined };
                },
                return(): Promise<IteratorResult<SseEvent>> {
                  returned();
                  if (mode === 'incomplete')
                    return Promise.resolve({
                      done: false,
                      value: { id: 'pending_1', type: 'update', data: 'Cleanup is incomplete' },
                    });
                  if (mode === 'malformed') return Promise.resolve(undefined as never);
                  if (mode === 'accessor')
                    return Promise.resolve({
                      get done() {
                        completionReads++;
                        return true as const;
                      },
                      value: undefined,
                    });
                  if (mode === 'proxy')
                    return Promise.resolve(
                      new Proxy(
                        { done: true as const, value: undefined },
                        {
                          get(target, key, receiver) {
                            if (key === 'done') completionReads++;
                            return Reflect.get(target, key, receiver);
                          },
                        },
                      ),
                    );
                  if (mode === 'inherited')
                    return Promise.resolve(
                      Object.create({ done: true, value: undefined }) as IteratorResult<SseEvent>,
                    );
                  const error = new Error('Private failed SSE cleanup diagnostic');
                  if (mode === 'throw') throw error;
                  if (mode === 'late-reject')
                    return new Promise<never>((_resolve, reject) => {
                      rejectCleanup = () => reject(error);
                    });
                  return Promise.reject(error);
                },
              };
              return iterator;
            },
          },
        },
      });
      let closeError: unknown, stopError: unknown;
      const authorization = await f.token();
      const request = get(f.origin + '/events', {
        headers: { authorization, accept: 'text/event-stream' },
      });
      request.on('error', () => undefined);
      try {
        await new Promise<void>((resolve, reject) => {
          request.once('response', (response) => {
            response.on('error', () => undefined);
            response.once('data', () => {
              response.destroy();
              resolve();
            });
          });
          request.once('error', reject);
        });
        await cleanup;
        await setImmediate();
        if (mode !== 'late-reject') {
          const status = await new Promise<number | undefined>((resolve, reject) => {
            const probe = get(
              f.origin + '/events',
              { headers: { authorization, accept: 'text/event-stream' } },
              (response) => {
                response.on('error', () => undefined);
                response.destroy();
                resolve(response.statusCode);
              },
            );
            probe.once('error', reject);
          });
          assert.equal(status, 503);
          assert.equal(allocations, 1);
          const tenant = f.app.auth!.tenantFrom(await f.app.auth!.verifyBearer(authorization));
          await assert.rejects(f.service.publish('updates', new Uint8Array([1]), tenant), {
            code: 'EK_REALTIME_CLOSED',
          });
        }
        const first = f.service.close(),
          repeated = f.service.close();
        assert.equal(first, repeated);
        const result = first.then(
          () => null,
          (error: unknown) => error,
        );
        if (mode === 'late-reject') {
          let settled = false;
          void result.then(() => {
            settled = true;
          });
          await setImmediate();
          assert.equal(settled, false);
          rejectCleanup();
        }
        closeError = await result;
      } finally {
        rejectCleanup();
        request.destroy();
        stopError = await f.close().then(
          () => null,
          (error: unknown) => error,
        );
      }
      assert.ok(closeError instanceof KitError);
      assert.equal(closeError.code, 'EK_BACKEND_UNAVAILABLE');
      assert.doesNotMatch(
        JSON.stringify(closeError.toSafeJSON()),
        /Private failed SSE cleanup diagnostic/,
      );
      assert.ok(stopError instanceof Error);
      assert.equal(completionReads, 0);
      assert.doesNotMatch(f.logs(), /Private failed SSE cleanup diagnostic/);
    },
  );

test(
  'Disconnect retains initial authentication capacity until the actual authority settles',
  { timeout: 5000 },
  async () => {
    let entered!: () => void,
      release!: () => void,
      aborted!: () => void,
      settled!: () => void,
      first = true;
    const called = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      }),
      cancelled = new Promise<void>((resolve) => {
        aborted = resolve;
      }),
      completed = new Promise<void>((resolve) => {
        settled = resolve;
      });
    const f = await fixture({
      policy: { maxConcurrent: 1, timeoutMs: 1000 },
      identityAuthority: {
        async authenticate(request, options) {
          if (first) {
            first = false;
            options?.signal?.addEventListener('abort', aborted, { once: true });
            entered();
            await gate;
          }
          const tenant = f.app.auth!.tenantFrom(
            await f.app.auth!.verifyBearer(request.headers.authorization),
          );
          settled();
          return tenant;
        },
      },
    });
    try {
      const authorization = await f.token();
      const outgoing = get(f.origin + '/events', {
        headers: { authorization, accept: 'text/event-stream' },
      });
      outgoing.on('error', () => undefined);
      await called;
      outgoing.destroy();
      await cancelled;
      assert.equal((await sseRequest(f.origin, { authorization })).status, 429);
      release();
      await completed;
      await setImmediate();
      assert.equal((await sseRequest(f.origin, { authorization })).status, 200);
    } finally {
      release();
      await f.close();
    }
  },
);

for (const mode of ['shutdown', 'disconnect'])
  test(
    `Backend cleanup failure after ${mode} remains visible and prevents new broadcast work`,
    { timeout: 5000 },
    async () => {
      let cleanupStarted!: () => void;
      const cleanupReady = new Promise<void>((resolve) => {
        cleanupStarted = resolve;
      });
      let cleaned = false,
        subscriptions = 0,
        publications = 0;
      const backend: MessageBus = {
        async publish() {
          publications++;
          return { messageId: 'fixture', acknowledged: false };
        },
        async subscribe() {
          subscriptions++;
          return {
            async close() {
              cleaned = true;
              cleanupStarted();
              throw new Error('private-backend-detail');
            },
          };
        },
      };
      const broker: Plugin = {
        id: 'messaging',
        version: '1.0.0',
        capabilities: new Set(['messaging']),
        init(context) {
          context.provide(COMPONENTS.messaging, backend);
        },
        close() {},
      };
      const f = await fixture(
        { pubsub: { provider: 'nats', connectionName: 'messaging' } },
        undefined,
        [broker],
      );
      let socket: WebSocket | undefined, probe: WebSocket | undefined;
      try {
        socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
          headers: { authorization: await f.token() },
        });
        await once(socket, 'open');
        if (mode === 'disconnect') {
          const closed = once(socket, 'close');
          socket.terminate();
          await closed;
          await cleanupReady;
          await setImmediate();
          assert.equal(cleaned, true);
          const authorization = await f.token();
          probe = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
            headers: { authorization },
          });
          probe.on('error', () => undefined);
          const status = await new Promise<number | undefined>((resolve) => {
            probe!.once('open', () => resolve(101));
            probe!.once('unexpected-response', (_request, response) => {
              response.resume();
              resolve(response.statusCode);
            });
          });
          assert.equal(status, 503);
          assert.equal(subscriptions, 1);
          const tenant = f.app.auth!.tenantFrom(await f.app.auth!.verifyBearer(authorization));
          await assert.rejects(f.service.publish('updates', new Uint8Array([1]), tenant), {
            code: 'EK_BACKEND_UNAVAILABLE',
          });
          assert.equal(publications, 0);
        }
        await assert.rejects(f.service.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
        assert.equal(cleaned, true);
        assert.ok(!f.logs().includes('private-backend-detail'));
      } finally {
        socket?.terminate();
        probe?.terminate();
        await assert.rejects(f.close());
      }
    },
  );
