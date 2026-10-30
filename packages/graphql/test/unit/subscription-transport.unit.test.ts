// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import mercurius from 'mercurius';
import WebSocket from 'ws';
import { COMPONENTS, APPLICATION_SIGNAL, KitError } from '@arkenivajs/core';
import type { AuthService, Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import type { GraphqlSubscriptionSource } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { compileSchema } from '../../dist/schema.js';
import { protectFields } from '../../dist/fields.js';
import { OwnedContexts } from '../../dist/contexts.js';
import { Operation } from '../../dist/operation.js';
import { SubscriptionExecution } from '../../dist/subscription-execution.js';
import { SubscriptionTransport } from '../../dist/subscription-transport.js';
import { subscriptionSocket } from '../../dist/subscription-socket.js';
import { fixture, tlsFiles, send } from '../fixture.js';

async function runtime(
  options: { plaintext?: boolean; source?: GraphqlSubscriptionSource; deadlineMs?: number } = {},
) {
  const tls = await tlsFiles();
  let capacity = 128,
    transport!: SubscriptionTransport,
    ready = true,
    allocations = 0,
    closes = 0;
  const active = new Set<Operation>();
  const settings = capture({
    path: '/pool-subscriptions',
    schema: 'type Query { ping: String } type Subscription { notice: String! }',
    resolvers: {
      Subscription: {
        notice: {
          subscribe:
            options.source ??
            async function* (_parent, _args, context) {
              allocations++;
              assert.ok(context.auth);
              try {
                yield context.auth.tenantId;
                if (!context.signal.aborted)
                  await new Promise<void>((resolve) =>
                    context.signal.addEventListener('abort', () => resolve(), { once: true }),
                  );
              } finally {
                closes++;
              }
            },
          resolve: (parent) => parent,
        },
      },
    },
    security: {
      auth: { required: true, scopes: ['graphql:read'] },
      authorizeField: () => true,
      limits: { maxOperationMs: options.deadlineMs ?? 1000 },
    },
    subscriptions: {
      enabled: true,
      pubsub: {
        subscribe() {
          throw new Error('The native fixture owns its explicit test source');
        },
        async publish() {},
        async close() {},
      },
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 4,
      revalidateIntervalMs: 5000,
      allowedOrigins: ['https://portal.example.test'],
    },
  });
  const probe: Plugin = {
    id: 'subscription-pool-probe',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['api', 'security'],
    async init(context) {
      const root = context.require<ManagedApiServer>(COMPONENTS.api).native(),
        scopes = new OwnedContexts<Operation>(),
        executions = new OwnedContexts<SubscriptionExecution>(),
        schema = compileSchema(settings);
      protectFields(schema, settings, scopes, executions);
      await subscriptionSocket(root);
      transport = new SubscriptionTransport(
        root,
        schema,
        settings,
        context.require<AuthService>(COMPONENTS.auth),
        context.require<AbortSignal>(APPLICATION_SIGNAL),
        scopes,
        executions,
        () => ready,
        (scope) => {
          if (active.size >= capacity)
            throw new KitError({
              code: 'EK_GQL_BACKPRESSURE',
              message: 'GraphQL execution capacity is exhausted',
            });
          active.add(scope);
          void scope.completion.then(() => active.delete(scope));
        },
      );
      root.register(async (child) => {
        child.addHook('onRequest', async (request, reply) => {
          if (request.headers.upgrade !== 'websocket') {
            await reply.code(404).send();
            return;
          }
          try {
            transport.handshake(request);
          } catch {
            await reply.code(403).send();
          }
        });
        await child.register(mercurius, {
          path: settings.path,
          schema,
          cache: false,
          jit: 0,
          graphiql: false,
          subscription: {
            fullWsTransport: false,
            context: (socket: WebSocket) => transport.context(socket),
          },
        });
        transport.install(child.graphql);
      });
    },
    close() {
      return transport.close();
    },
  };
  try {
    const f = await fixture(undefined, {
      ...(options.plaintext ? {} : { tls: tls.tls }),
      plugins: [probe],
    });
    const wires = new Set<WebSocket>();
    return {
      f,
      transport,
      active,
      allocations: () => allocations,
      closes: () => closes,
      readiness(value: boolean) {
        ready = value;
      },
      capacity(value: number) {
        capacity = value;
      },
      async connect(
        options: {
          origin?: string;
          protocol?: string | string[];
          headers?: Record<string, string>;
          suffix?: string;
          initialize?: boolean;
          tenant?: string;
        } = {},
      ) {
        const socket = new WebSocket(
          f.origin.replace('https:', 'wss:').replace('http:', 'ws:') +
            settings.path +
            (options.suffix ?? ''),
          options.protocol ?? 'graphql-transport-ws',
          {
            ca: tls.ca,
            origin: options.origin ?? 'https://portal.example.test',
            ...(options.headers ? { headers: options.headers } : {}),
          },
        );
        wires.add(socket);
        await once(socket, 'open');
        if (options.initialize !== false) {
          const ack = Promise.race([
            once(socket, 'message'),
            once(socket, 'close').then(() => {
              throw new Error('Connection closed before the native ACK');
            }),
          ]);
          socket.send(
            JSON.stringify({
              type: 'connection_init',
              payload: { authorization: await f.token(options.tenant ?? 'tenant-a') },
            }),
          );
          assert.equal(JSON.parse(String((await ack)[0])).type, 'connection_ack');
        }
        return socket;
      },
      async query() {
        return send(
          f.origin,
          { query: '{ ping }' },
          { ca: tls.ca, headers: { authorization: await f.token() } },
        );
      },
      async close() {
        for (const wire of wires) wire.terminate();
        try {
          await f.close();
        } finally {
          await tls.close();
        }
      },
    };
  } catch (error) {
    await tls.close();
    throw error;
  }
}
async function until(check: () => boolean) {
  for (let index = 0; index < 200 && !check(); index++) await delay(5);
  assert.ok(check());
}
const start = (socket: WebSocket) =>
  socket.send('{"type":"subscribe","id":"one","payload":{"query":"subscription { notice }"}}');

test(
  'Global native connection capacity remains bounded across idle sockets and recovers only after retirement',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const first = await r.connect(),
        second = await r.connect();
      assert.equal(r.transport.stats().connections, 2);
      await assert.rejects(r.connect(), /403/);
      const closed = once(first, 'close');
      first.close();
      await closed;
      await until(() => r.transport.stats().connections === 1);
      await r.connect();
      assert.equal(r.transport.stats().connections, 2);
      assert.equal(r.transport.stats().activeSubscriptions, 0);
      assert.equal(r.active.size, 0);
      assert.equal(second.readyState, WebSocket.OPEN);
      assert.equal((await r.query()).status, 200);
    } finally {
      await r.close();
    }
  },
);

test(
  'The shared listener enforces exact origin, protocol, cookie and URL policies before allocating native owners',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      for (const options of [
        { origin: 'https://untrusted.example.test' },
        { protocol: 'graphql-ws' },
        { protocol: ['graphql-transport-ws', 'graphql-ws'] },
        { headers: { cookie: '' } },
        { suffix: '?authorization=untrusted' },
      ])
        await assert.rejects(r.connect(options), /403/);
      assert.equal(r.transport.stats().connections, 0);
      assert.equal(r.allocations(), 0);
      r.readiness(false);
      await assert.rejects(r.connect(), /403/);
      r.readiness(true);
      const socket = await r.connect();
      const value = once(socket, 'message');
      start(socket);
      assert.deepEqual(JSON.parse(String((await value)[0])), {
        type: 'next',
        id: 'one',
        payload: { data: { notice: 'tenant-a' } },
      });
      await until(() => r.active.size === 0);
      assert.equal(r.transport.stats().activeSubscriptions, 1);
      await r.transport.close();
      assert.equal(r.transport.stats().connections, 0);
      assert.equal(r.transport.stats().ready, false);
      assert.equal(r.closes(), 1);
      await assert.rejects(r.connect(), /403/);
    } finally {
      await r.close();
    }
  },
);

test(
  'Plain WebSocket upgrades are rejected even on a test-only HTTP application listener',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ plaintext: true });
    try {
      await assert.rejects(r.connect(), /403/);
      assert.equal(r.transport.stats().connections, 0);
    } finally {
      await r.close();
    }
  },
);

for (const retirement of ['reject', 'incomplete'])
  test(
    `Provider ${retirement} retirement quarantines the transport even after its connection count reaches zero`,
    { timeout: 10000 },
    async () => {
      const r = await runtime({
        source(_parent, _args, context) {
          let delivered = false,
            wake: ((value: IteratorResult<unknown>) => void) | undefined;
          context.signal.addEventListener('abort', () => wake?.({ done: true, value: undefined }), {
            once: true,
          });
          const iterator: AsyncIterableIterator<unknown> = {
            [Symbol.asyncIterator]() {
              return this;
            },
            next() {
              if (!delivered) {
                delivered = true;
                return Promise.resolve({ done: false, value: context.auth!.tenantId });
              }
              if (context.signal.aborted) return Promise.resolve({ done: true, value: undefined });
              return new Promise((resolve) => {
                wake = resolve;
              });
            },
            async return() {
              if (retirement === 'reject') throw new Error('Private provider cleanup failure');
              return { done: false, value: 'Provider cleanup remains incomplete' };
            },
          };
          return iterator;
        },
      });
      try {
        const socket = await r.connect(),
          value = once(socket, 'message');
        start(socket);
        await value;
        const closed = once(socket, 'close');
        socket.send('{"type":"complete","id":"one"}');
        await closed;
        await until(() => r.transport.stats().connections === 0);
        assert.equal(r.transport.stats().degraded, true);
        assert.equal(r.transport.stats().ready, false);
        await assert.rejects(r.connect(), /403/);
        assert.equal(r.active.size, 0);
      } finally {
        await r.close();
      }
    },
  );

test(
  'A timed-out transport shutdown retains late physical acquisition until its real iterator is returned',
  { timeout: 10000 },
  async () => {
    let provide!: (source: AsyncIterable<unknown>) => void,
      signal: AbortSignal | undefined,
      returns = 0;
    const pending = new Promise<AsyncIterable<unknown>>((resolve) => {
      provide = resolve;
    });
    const source: AsyncIterableIterator<unknown> = {
      [Symbol.asyncIterator]() {
        return this;
      },
      async next() {
        return { done: true, value: undefined };
      },
      async return() {
        returns++;
        return { done: true, value: undefined };
      },
    };
    const r = await runtime({
      deadlineMs: 500,
      source(_parent, _args, context) {
        signal = context.signal;
        return pending;
      },
    });
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => signal !== undefined);
      await assert.rejects(r.transport.close(), { code: 'EK_TIMEOUT' });
      assert.equal(signal?.aborted, true);
      assert.equal(r.transport.stats().connections, 1);
      assert.equal(r.transport.stats().ready, false);
      provide(source);
      await until(() => r.transport.stats().connections === 0);
      assert.equal(returns, 1);
      assert.equal(r.active.size, 0);
    } finally {
      provide(source);
      await r.close().catch((error: unknown) => {
        assert.ok(error instanceof KitError && error.code === 'EK_TIMEOUT');
      });
    }
  },
);

test(
  'Native start capacity failures retain their stable error code without allocating a source',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const socket = await r.connect();
      r.capacity(0);
      const error = once(socket, 'message'),
        closed = once(socket, 'close');
      start(socket);
      const frame = JSON.parse(String((await error)[0]));
      assert.equal(frame.type, 'error');
      assert.equal(frame.payload[0].extensions.code, 'EK_GQL_BACKPRESSURE');
      await closed;
      await until(() => r.transport.stats().connections === 0);
      assert.equal(r.allocations(), 0);
      assert.equal(r.active.size, 0);
      assert.equal(r.transport.stats().degraded, false);
    } finally {
      await r.close();
    }
  },
);

test(
  'A failed source read with confirmed retirement closes only its connection and preserves another tenant',
  { timeout: 10000 },
  async () => {
    let returns = 0;
    const r = await runtime({
      source: async function* (_parent, _args, context) {
        try {
          yield context.auth!.tenantId;
          if (context.auth!.tenantId === 'tenant-a')
            throw new Error('Private tenant-local source read failure');
          if (!context.signal.aborted)
            await new Promise<void>((resolve) =>
              context.signal.addEventListener('abort', () => resolve(), { once: true }),
            );
        } finally {
          returns++;
        }
      },
    });
    try {
      const a = await r.connect(),
        closed = once(a, 'close'),
        first = once(a, 'message');
      start(a);
      assert.equal(JSON.parse(String((await first)[0])).payload.data.notice, 'tenant-a');
      await closed;
      await until(() => r.transport.stats().connections === 0);
      assert.equal(returns, 1);
      assert.equal(r.transport.stats().degraded, false);
      assert.equal(r.transport.stats().ready, true);
      const b = await r.connect({ tenant: 'tenant-b' }),
        next = once(b, 'message');
      start(b);
      assert.equal(JSON.parse(String((await next)[0])).payload.data.notice, 'tenant-b');
      assert.equal(r.transport.stats().activeSubscriptions, 1);
    } finally {
      await r.close();
    }
  },
);

test(
  'A real paused WSS consumer is terminated under its write bound without exhausting another tenant connection',
  { timeout: 10000 },
  async () => {
    let retired = 0,
      emitted = 0;
    const payload = 'x'.repeat(524288);
    const r = await runtime({
      deadlineMs: 300,
      source: async function* (_parent, _args, context) {
        try {
          if (context.auth!.tenantId === 'tenant-a') {
            while (!context.signal.aborted) {
              emitted++;
              yield payload;
            }
          } else {
            yield 'healthy-tenant-b';
            if (!context.signal.aborted)
              await new Promise<void>((resolve) =>
                context.signal.addEventListener('abort', () => resolve(), { once: true }),
              );
          }
        } finally {
          retired++;
        }
      },
    });
    let paused: WebSocket | undefined;
    try {
      paused = await r.connect();
      paused.pause();
      start(paused);
      await until(() => r.transport.stats().connections === 0);
      assert.ok(emitted > 1);
      assert.equal(retired, 1);
      assert.equal(r.active.size, 0);
      assert.equal(r.transport.stats().degraded, false);
      paused.resume();
      const healthy = await r.connect({ tenant: 'tenant-b' }),
        received = once(healthy, 'message');
      start(healthy);
      assert.deepEqual(JSON.parse(String((await received)[0])), {
        type: 'next',
        id: 'one',
        payload: { data: { notice: 'healthy-tenant-b' } },
      });
    } finally {
      paused?.resume();
      await r.close();
    }
  },
);
