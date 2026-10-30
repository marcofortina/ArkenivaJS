// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import type { GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { fixture, tlsFiles } from '../fixture.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function until(check: () => boolean) {
  for (let attempt = 0; attempt < 300 && !check(); attempt++) await delay(5);
  assert.ok(check(), 'The public subscription did not reach its owned lifecycle state');
}

for (const cancellation of ['client-close', 'deadline'] as const)
  test(
    `Public WSS ${cancellation} retains a pending event authorization until late approval retires without mapping or getters`,
    { timeout: 15000 },
    async () => {
      const entered = deferred(),
        gate = deferred(),
        tls = await tlsFiles(),
        channels = new Map<string, (value: unknown) => void>(),
        stops = new Set<() => void>(),
        mappings = new Map<string, number>(),
        getters = new Map<string, number>();
      let holdEvents = false,
        pending = 0,
        policyCalls = 0,
        acquired = 0,
        retired = 0,
        policySignal: AbortSignal | undefined;
      const verify = (tenant: VerifiedTenantContext) => {
        assert.ok(auth);
        assert.equal(auth.tenantFrom(tenant.identity), tenant);
      };
      const pubsub: GraphqlSubscriptionPubSub = {
        subscribe(topic, tenant, options) {
          verify(tenant);
          assert.equal(topic, 'notices');
          assert.equal(channels.has(tenant.tenantId), false);
          acquired++;
          let wake: ((value: IteratorResult<unknown>) => void) | undefined,
            closed = false;
          const queue: unknown[] = [];
          const stop = () => {
            if (closed) return;
            closed = true;
            retired++;
            channels.delete(tenant.tenantId);
            stops.delete(stop);
            options?.signal?.removeEventListener('abort', stop);
            wake?.({ done: true, value: undefined });
            wake = undefined;
          };
          stops.add(stop);
          options?.signal?.addEventListener('abort', stop, { once: true });
          channels.set(tenant.tenantId, (value) => {
            assert.equal(closed, false);
            if (wake) {
              const receive = wake;
              wake = undefined;
              receive({ done: false, value });
            } else {
              assert.equal(queue.length, 0);
              queue.push(value);
            }
          });
          const source: AsyncIterableIterator<unknown> = {
            [Symbol.asyncIterator]() {
              return this;
            },
            next() {
              if (closed) return Promise.resolve({ done: true, value: undefined });
              if (queue.length) return Promise.resolve({ done: false, value: queue.shift() });
              assert.equal(wake, undefined);
              return new Promise<IteratorResult<unknown>>((resolve) => {
                wake = resolve;
              });
            },
            async return() {
              stop();
              return { done: true, value: undefined };
            },
          };
          return source;
        },
        async publish(topic, value, tenant) {
          verify(tenant);
          assert.equal(topic, 'notices');
          assert.ok(channels.has(tenant.tenantId));
          channels.get(tenant.tenantId)!(value);
        },
        async close() {
          for (const stop of stops) stop();
        },
      };
      const f = await fixture(
        {
          schema:
            'type Notice { value: String! } type Query { ping: String! } type Subscription { notice: Notice! }',
          resolvers: {
            Query: { ping: () => 'pong' },
            Subscription: {
              notice: {
                subscribe(_parent, _args, context) {
                  return pubsub.subscribe('notices', context.auth!, { signal: context.signal });
                },
                resolve(parent, _args, context) {
                  const tenant = context.auth!.tenantId;
                  mappings.set(tenant, (mappings.get(tenant) ?? 0) + 1);
                  return parent;
                },
              },
            },
          },
          security: {
            auth: { required: true, scopes: ['graphql:read'] },
            limits: { maxOperationMs: cancellation === 'deadline' ? 1000 : 5000 },
            async authorizeField({ context, field }) {
              if (
                holdEvents &&
                context.auth?.tenantId === 'tenant-a' &&
                field.parentType === 'Subscription' &&
                field.fieldName === 'notice'
              ) {
                policyCalls++;
                pending++;
                policySignal = context.signal;
                entered.resolve();
                // This real application policy ignores cancellation until its backend settles.
                try {
                  await gate.promise;
                } finally {
                  pending--;
                }
              }
              return true;
            },
          },
          subscriptions: {
            enabled: true,
            pubsub,
            maxConnections: 3,
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
      const sockets = new Set<WebSocket>();
      const connect = async (tenant: string) => {
        const socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          { ca: tls.ca, origin: 'https://portal.example.test' },
        );
        sockets.add(socket);
        await once(socket, 'open');
        const ack = once(socket, 'message');
        socket.send(
          JSON.stringify({
            type: 'connection_init',
            payload: { authorization: await f.token(tenant) },
          }),
        );
        assert.deepEqual(JSON.parse(String((await ack)[0])), { type: 'connection_ack' });
        const values: unknown[] = [];
        socket.on('message', (raw) => {
          const frame = JSON.parse(String(raw));
          if (frame.type === 'ping') socket.send('{"type":"pong"}');
          else if (frame.type === 'next') values.push(frame.payload);
        });
        socket.send(
          '{"type":"subscribe","id":"owned","payload":{"query":"subscription { notice { value } }"}}',
        );
        return { socket, values };
      };
      const publish = async (tenant: string, value: string) => {
        const identity = await auth!.verifyBearer(await f.token(tenant));
        await pubsub.publish(
          'notices',
          {
            get value() {
              getters.set(tenant, (getters.get(tenant) ?? 0) + 1);
              return value;
            },
          },
          auth!.tenantFrom(identity),
        );
      };
      try {
        const first = await connect('tenant-a'),
          other = await connect('tenant-b');
        await until(() => acquired === 2);
        await publish('tenant-a', 'before-policy-pause');
        await until(() => first.values.length === 1);
        assert.deepEqual(first.values, [{ data: { notice: { value: 'before-policy-pause' } } }]);
        assert.equal(mappings.get('tenant-a'), 1);
        assert.equal(getters.get('tenant-a'), 1);
        holdEvents = true;
        const closed = once(first.socket, 'close');
        await publish('tenant-a', 'must-not-execute-after-cancellation');
        await entered.promise;
        assert.equal(pending, 1);
        if (cancellation === 'client-close') first.socket.close();
        await closed;
        await until(() => policySignal?.aborted === true);
        assert.equal(policyCalls, 1);
        assert.equal(pending, 1);
        assert.ok(f.service.stats().activeOperations >= 1);
        assert.equal(mappings.get('tenant-a'), 1);
        assert.equal(getters.get('tenant-a'), 1);
        await publish('tenant-b', 'healthy-while-other-policy-pending');
        await until(() => other.values.length === 1);
        assert.deepEqual(other.values, [
          { data: { notice: { value: 'healthy-while-other-policy-pending' } } },
        ]);
        assert.equal(pending, 1);
        assert.ok(f.service.stats().activeOperations >= 1);
        gate.resolve();
        await until(() => pending === 0 && f.service.stats().activeOperations === 0);
        await until(() => retired === 1 && f.service.stats().activeSubscriptions === 1);
        assert.equal(first.values.length, 1);
        assert.equal(mappings.get('tenant-a'), 1);
        assert.equal(getters.get('tenant-a'), 1);
        holdEvents = false;
        const recovered = await connect('tenant-a');
        await until(() => acquired === 3);
        await publish('tenant-a', 'recovered-policy-owner');
        await until(() => recovered.values.length === 1);
        assert.deepEqual(recovered.values, [
          { data: { notice: { value: 'recovered-policy-owner' } } },
        ]);
        assert.equal(mappings.get('tenant-a'), 2);
        assert.equal(getters.get('tenant-a'), 2);
        assert.equal(other.values.length, 1);
        assert.equal(first.values.length, 1);
        assert.equal(f.service.health().subscriptionsReady, true);
        assert.doesNotMatch(f.logs(), /must-not-execute-after-cancellation|Bearer /);
      } finally {
        gate.resolve();
        for (const socket of sockets) socket.terminate();
        try {
          await f.close();
        } finally {
          await pubsub.close();
          await tls.close();
        }
      }
      assert.equal(retired, acquired);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(f.service.stats().activeSubscriptions, 0);
    },
  );
