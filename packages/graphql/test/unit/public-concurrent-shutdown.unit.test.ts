// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { fixture, send, tlsFiles } from '../fixture.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function bounded<T>(promise: Promise<T>): Promise<T> {
  const controller = new AbortController();
  try {
    return await Promise.race([
      promise,
      delay(5000, undefined, { signal: controller.signal }).then(() => {
        throw new Error('The owned GraphQL shutdown observation exceeded its deadline');
      }),
    ]);
  } finally {
    controller.abort();
  }
}

async function until(check: () => boolean) {
  for (let attempt = 0; attempt < 600 && !check(); attempt++) await delay(5);
  assert.ok(check(), 'Owned GraphQL work did not physically retire');
}

for (const scenario of [
  { name: 'application deadline', maxOperationMs: 5000, stopTimeoutMs: 100 },
  { name: 'subscription retirement deadline', maxOperationMs: 200, stopTimeoutMs: 2000 },
]) {
  test(
    `Concurrent HTTPS and WSS shutdown retains uncooperative work at the ${scenario.name}`,
    { timeout: 20000 },
    async () => {
      const tls = await tlsFiles(),
        resolverEntered = deferred(),
        resolverRelease = deferred(),
        nextEntered = deferred(),
        returnEntered = deferred(),
        returnRelease = deferred(),
        resolverRetired = deferred(),
        sourceRetired = deferred();
      let resources = 0,
        returns = 0,
        acquired = 0,
        nextCalls = 0,
        resolverSettled = false,
        returnSettled = false,
        nextSettled = false,
        sourceClosed = false,
        resolverSignal: AbortSignal | undefined,
        sourceSignal: AbortSignal | undefined,
        wake: ((value: IteratorResult<unknown>) => void) | undefined;
      const pubsub: GraphqlSubscriptionPubSub = {
        subscribe(topic, tenant, options) {
          assert.ok(auth);
          assert.equal(auth.tenantFrom(tenant.identity), tenant);
          assert.equal(tenant.tenantId, 'tenant-a');
          assert.equal(topic, 'held-notices');
          assert.equal(++acquired, 1);
          sourceSignal = options?.signal;
          assert.ok(sourceSignal);
          resources++;
          const source: AsyncIterableIterator<unknown> = {
            [Symbol.asyncIterator]() {
              return this;
            },
            next() {
              if (sourceClosed) return Promise.resolve({ done: true, value: undefined });
              assert.equal(++nextCalls, 1);
              assert.equal(wake, undefined);
              nextEntered.resolve();
              return new Promise<IteratorResult<unknown>>((resolve) => {
                wake = (value) => {
                  nextSettled = true;
                  resolve(value);
                };
              });
            },
            async return() {
              assert.equal(++returns, 1);
              returnEntered.resolve();
              // Cancellation is observable, but this provider still owns its resource.
              await returnRelease.promise;
              sourceClosed = true;
              resources--;
              const receive = wake;
              wake = undefined;
              receive?.({ done: true, value: undefined });
              returnSettled = true;
              sourceRetired.resolve();
              return { done: true, value: undefined };
            },
          };
          return source;
        },
        async publish() {
          throw new Error('This shutdown source does not publish application data');
        },
        async close() {
          assert.equal(resources, 0);
        },
      };
      const f = await fixture(
        {
          schema: 'type Query { held: String! } type Subscription { notice: String! }',
          resolvers: {
            Query: {
              async held(_parent, _args, context) {
                assert.ok(auth && context.auth);
                assert.equal(auth.tenantFrom(context.auth.identity), context.auth);
                assert.equal(context.auth.tenantId, 'tenant-a');
                resolverSignal = context.signal;
                resolverEntered.resolve();
                try {
                  await resolverRelease.promise;
                  return 'private-late-result-after-shutdown';
                } finally {
                  resolverSettled = true;
                  resolverRetired.resolve();
                }
              },
            },
            Subscription: {
              notice: {
                subscribe(_parent, _args, context) {
                  return pubsub.subscribe('held-notices', context.auth!, {
                    signal: context.signal,
                  });
                },
                resolve: (parent) => parent,
              },
            },
          },
          security: {
            auth: { required: true, scopes: ['graphql:read'] },
            authorizeField: () => true,
            limits: { maxOperationMs: scenario.maxOperationMs },
          },
          subscriptions: {
            enabled: true,
            pubsub,
            maxConnections: 2,
            maxOperationsPerConnection: 2,
            maxQueuedEventsPerConnection: 4,
            revalidateIntervalMs: 5000,
            allowedOrigins: ['https://portal.example.test'],
          },
        },
        { tls: tls.tls },
      ).catch(async (error: unknown) => {
        await tls.close();
        throw error;
      });
      const auth = f.app.resolve<AuthService>(COMPONENTS.auth);
      let socket: WebSocket | undefined, pending: Promise<unknown> | undefined;
      const native = f.api.native(),
        frames: unknown[] = [];
      try {
        const authorization = await f.token();
        socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          {
            ca: tls.ca,
            origin: 'https://portal.example.test',
          },
        );
        socket.on('error', () => undefined);
        await bounded(once(socket, 'open'));
        const ack = once(socket, 'message');
        socket.send(JSON.stringify({ type: 'connection_init', payload: { authorization } }));
        assert.deepEqual(JSON.parse(String((await bounded(ack))[0])), { type: 'connection_ack' });
        socket.on('message', (raw) => {
          const frame = JSON.parse(String(raw));
          if (frame.type === 'ping') socket!.send('{"type":"pong"}');
          else frames.push(frame);
        });
        socket.send(
          '{"type":"subscribe","id":"owned-shutdown","payload":{"query":"subscription { notice }"}}',
        );
        await bounded(nextEntered.promise);
        pending = send(
          f.origin,
          { query: '{ held }' },
          { ca: tls.ca, headers: { authorization } },
        ).then(
          (value) => value,
          (error: unknown) => error,
        );
        await bounded(resolverEntered.promise);
        assert.equal(resources, 1);
        assert.equal(f.service.stats().activeSubscriptions, 1);
        assert.equal(f.service.stats().activeOperations, 1);
        assert.equal(resolverSignal?.aborted, false);
        assert.equal(sourceSignal?.aborted, false);
        const wireClosed = once(socket, 'close'),
          stopping = f.app.stop({ timeoutMs: scenario.stopTimeoutMs });
        assert.equal(f.app.stop({ timeoutMs: scenario.stopTimeoutMs }), stopping);
        await assert.rejects(stopping, { code: 'EK_TIMEOUT' });
        await bounded(returnEntered.promise);
        await bounded(wireClosed);
        await until(() => !native.server.listening);
        assert.equal(f.app.state, 'CLOSED');
        assert.equal(f.service.health().ready, false);
        assert.equal(f.service.health().subscriptionsReady, false);
        assert.equal(resolverSignal?.aborted, true);
        assert.equal(sourceSignal?.aborted, true);
        assert.equal(returns, 1);
        assert.equal(resources, 1);
        assert.equal(resolverSettled, false);
        assert.equal(returnSettled, false);
        assert.equal(nextSettled, false);
        assert.equal(f.service.stats().activeOperations, 1);
        assert.equal(f.service.stats().activeSubscriptions, 1);
        assert.equal(socket.readyState, WebSocket.CLOSED);
        assert.deepEqual(frames, []);
        await f.app.stop();
        assert.equal(resources, 1);
        assert.equal(resolverSettled, false);
        assert.equal(returnSettled, false);
      } finally {
        // Release only after the timeout/retained-ownership assertions, including failure paths.
        resolverRelease.resolve();
        returnRelease.resolve();
        socket?.terminate();
        try {
          if (resolverSignal) await bounded(resolverRetired.promise);
          if (acquired) await bounded(sourceRetired.promise);
          await bounded(Promise.resolve(pending));
          await bounded(f.api.close()).catch((error: unknown) => {
            // A repeated public close retains the original forced-shutdown rejection.
            if (!(error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code)))
              return Promise.reject(error);
          });
          await until(
            () =>
              f.service.stats().activeOperations === 0 &&
              f.service.stats().activeSubscriptions === 0,
          );
          assert.equal(resources, 0);
          assert.equal(returns, acquired);
          assert.doesNotMatch(f.logs(), /private-late-result-after-shutdown|Bearer /);
        } finally {
          try {
            await f.close();
          } finally {
            await pubsub.close();
            await tls.close();
          }
        }
      }
      const rebound = createServer();
      try {
        const listening = once(rebound, 'listening');
        rebound.listen(Number(new URL(f.origin).port), '127.0.0.1');
        await bounded(listening);
      } finally {
        if (rebound.listening)
          await new Promise<void>((resolve, reject) =>
            rebound.close((error) => (error ? reject(error) : resolve())),
          );
      }
      assert.equal(resources, 0);
      assert.equal(resolverSettled, true);
      assert.equal(returnSettled, true);
      assert.equal(nextSettled, true);
      assert.equal(returns, 1);
    },
  );
}
