// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { fixture, send, tlsFiles } from '../fixture.js';

async function until(check: () => boolean) {
  for (let attempt = 0; attempt < 300 && !check(); attempt++) await delay(5);
  assert.ok(check(), 'The public subscription did not finish its physical retirement');
}

test(
  'A failed real public WSS source retirement degrades future subscriptions while authenticated HTTP remains healthy',
  { timeout: 15000 },
  async () => {
    const tls = await tlsFiles();
    let acquired = 0,
      returns = 0,
      resources = 0,
      queryCalls = 0,
      wake: ((value: IteratorResult<unknown>) => void) | undefined,
      closed = false;
    const pubsub: GraphqlSubscriptionPubSub = {
      subscribe(topic, tenant) {
        assert.ok(auth);
        assert.equal(auth.tenantFrom(tenant.identity), tenant);
        assert.equal(topic, 'notices');
        assert.equal(acquired, 0);
        acquired++;
        resources++;
        const source: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return this;
          },
          next() {
            if (closed) return Promise.resolve({ done: true, value: undefined });
            assert.equal(wake, undefined);
            return new Promise<IteratorResult<unknown>>((resolve) => {
              wake = resolve;
            });
          },
          async return() {
            assert.equal(++returns, 1);
            closed = true;
            resources--;
            wake?.({ done: true, value: undefined });
            wake = undefined;
            throw new Error('Private subscription provider retirement failure');
          },
        };
        return source;
      },
      async publish(topic, value, tenant) {
        assert.ok(auth);
        assert.equal(auth.tenantFrom(tenant.identity), tenant);
        assert.equal(topic, 'notices');
        assert.ok(wake);
        const receive = wake;
        wake = undefined;
        receive({ done: false, value });
      },
      async close() {
        assert.equal(resources, 0);
      },
    };
    const f = await fixture(
      {
        schema: 'type Query { ping: String! } type Subscription { notice: String! }',
        resolvers: {
          Query: {
            ping() {
              queryCalls++;
              return 'healthy-http-after-subscription-failure';
            },
          },
          Subscription: {
            notice: {
              subscribe(_parent, _args, context) {
                return pubsub.subscribe('notices', context.auth!, { signal: context.signal });
              },
              resolve: (parent) => parent,
            },
          },
        },
        security: {
          auth: { required: true, scopes: ['graphql:read'] },
          authorizeField: () => true,
          limits: { maxOperationMs: 1000 },
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
    let socket: WebSocket | undefined, denied: WebSocket | undefined;
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
      await once(socket, 'open');
      const ack = once(socket, 'message');
      socket.send(JSON.stringify({ type: 'connection_init', payload: { authorization } }));
      assert.deepEqual(JSON.parse(String((await ack)[0])), { type: 'connection_ack' });
      const frames: unknown[] = [];
      socket.on('message', (raw) => {
        const frame = JSON.parse(String(raw));
        if (frame.type === 'ping') socket!.send('{"type":"pong"}');
        else frames.push(frame);
      });
      socket.send(
        '{"type":"subscribe","id":"owned","payload":{"query":"subscription { notice }"}}',
      );
      await until(() => acquired === 1 && wake !== undefined);
      const identity = await auth.verifyBearer(authorization);
      await pubsub.publish('notices', 'before-retirement-failure', auth.tenantFrom(identity));
      await until(() => frames.length === 1);
      assert.deepEqual(frames, [
        { type: 'next', id: 'owned', payload: { data: { notice: 'before-retirement-failure' } } },
      ]);
      assert.equal(resources, 1);
      assert.equal(f.service.health().subscriptionsReady, true);
      const terminal = once(socket, 'close');
      socket.send('{"type":"complete","id":"owned"}');
      await terminal;
      await until(
        () =>
          returns === 1 &&
          resources === 0 &&
          f.service.stats().activeOperations === 0 &&
          f.service.stats().activeSubscriptions === 0,
      );
      assert.equal(f.service.health().subscriptionsReady, false);
      assert.equal(acquired, 1);
      denied = new WebSocket(
        f.origin.replace('https:', 'wss:') + '/graphql',
        'graphql-transport-ws',
        { ca: tls.ca, origin: 'https://portal.example.test' },
      );
      let opened = false;
      denied.on('open', () => {
        opened = true;
      });
      denied.on('error', () => undefined);
      const rejection = await new Promise<number>((resolve, reject) => {
        denied!.once('unexpected-response', (_request, response) => {
          response.resume();
          response.once('end', () => resolve(response.statusCode!));
          response.once('error', reject);
        });
      });
      assert.ok(rejection >= 400);
      assert.equal(opened, false);
      assert.equal(acquired, 1);
      const healthy = await send(
        f.origin,
        { query: '{ ping }' },
        { ca: tls.ca, headers: { authorization: await f.token('tenant-b') } },
      );
      assert.equal(healthy.status, 200, healthy.body);
      assert.deepEqual(healthy.json(), {
        data: { ping: 'healthy-http-after-subscription-failure' },
      });
      assert.equal(queryCalls, 1);
      assert.equal(f.service.health().subscriptionsReady, false);
      assert.equal(f.service.stats().activeOperations, 0);
      assert.equal(returns, 1);
      assert.doesNotMatch(f.logs(), /Private subscription provider retirement failure|Bearer /);
    } finally {
      socket?.terminate();
      denied?.terminate();
      try {
        await f.close();
      } finally {
        await pubsub.close();
        await tls.close();
      }
    }
    assert.equal(resources, 0);
    assert.equal(returns, 1);
  },
);
