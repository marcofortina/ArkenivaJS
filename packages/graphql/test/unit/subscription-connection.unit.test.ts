// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import mercurius from 'mercurius';
import type { FastifyRequest } from 'fastify';
import WebSocket from 'ws';
import type { WebSocketServer } from 'ws';
import { COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { AuthService, Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import type { GraphqlSubscriptionSource } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { compileSchema } from '../../dist/schema.js';
import { protectFields } from '../../dist/fields.js';
import { OwnedContexts } from '../../dist/contexts.js';
import { Operation } from '../../dist/operation.js';
import { SubscriptionExecution } from '../../dist/subscription-execution.js';
import { SubscriptionConnection } from '../../dist/subscription-connection.js';
import { subscriptionSocket } from '../../dist/subscription-socket.js';
import { fixture, tlsFiles, send } from '../fixture.js';

async function runtime(
  options: {
    source?: GraphqlSubscriptionSource;
    revalidateMs?: number;
    deadlineMs?: number;
    authorize?: () => boolean;
    owner?: AbortSignal;
  } = {},
) {
  const tls = await tlsFiles();
  const owners: SubscriptionConnection[] = [],
    active = new Set<Operation>(),
    channels = new Map<string, Set<(value: unknown) => void>>();
  let revoked = false,
    closed = 0,
    allocated = 0;
  const source: GraphqlSubscriptionSource = (_parent, _args, context) => {
    assert.ok(context.auth);
    allocated++;
    const tenant = context.auth.tenantId;
    const listeners = channels.get(tenant) ?? new Set<(value: unknown) => void>();
    channels.set(tenant, listeners);
    let wake: ((value: IteratorResult<unknown>) => void) | undefined;
    let stopped = false;
    const queue: unknown[] = [];
    const deliver = (value: unknown) => {
      if (stopped) return;
      if (wake) {
        const pending = wake;
        wake = undefined;
        pending({ done: false, value });
      } else {
        assert.ok(queue.length < 2);
        queue.push(value);
      }
    };
    const stop = () => {
      if (stopped) return;
      stopped = true;
      closed++;
      listeners.delete(deliver);
      context.signal.removeEventListener('abort', stop);
      wake?.({ done: true, value: undefined });
      wake = undefined;
    };
    listeners.add(deliver);
    context.signal.addEventListener('abort', stop, { once: true });
    const iterator: AsyncIterableIterator<unknown> = {
      [Symbol.asyncIterator]() {
        return this;
      },
      next() {
        if (stopped) return Promise.resolve({ done: true, value: undefined });
        if (queue.length) return Promise.resolve({ done: false, value: queue.shift() });
        return new Promise<IteratorResult<unknown>>((resolve) => {
          wake = resolve;
        });
      },
      async return() {
        stop();
        return { done: true, value: undefined };
      },
    };
    return iterator;
  };
  const settings = capture({
    schema: 'type Query { ping: String } type Subscription { notice(tenantHint: String): String! }',
    resolvers: {
      Subscription: {
        notice: { subscribe: options.source ?? source, resolve: (parent) => parent },
      },
    },
    security: {
      auth: { required: true, scopes: ['graphql:read'] },
      authorizeField: options.authorize ?? (() => true),
      limits: { maxOperationMs: options.deadlineMs ?? 1000 },
    },
    subscriptions: {
      enabled: true,
      pubsub: {
        subscribe() {
          throw new Error('This engine fixture owns its test source explicitly');
        },
        async publish() {},
        async close() {},
      },
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 4,
      revalidateIntervalMs: options.revalidateMs ?? 5000,
      allowedOrigins: ['https://portal.example.test'],
    },
  });
  const probe: Plugin = {
    id: 'owned-subscription-probe',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['api', 'security'],
    async init(context) {
      const root = context.require<ManagedApiServer>(COMPONENTS.api).native(),
        authority = context.require<AuthService>(COMPONENTS.auth),
        signal = context.require<AbortSignal>(APPLICATION_SIGNAL),
        scopes = new OwnedContexts<Operation>(),
        executions = new OwnedContexts<SubscriptionExecution>(),
        connections = new OwnedContexts<SubscriptionConnection>(),
        sockets = new WeakMap<WebSocket, SubscriptionConnection>(),
        requests = new WeakMap<object, FastifyRequest>(),
        schema = compileSchema(settings);
      protectFields(schema, settings, scopes, executions);
      await subscriptionSocket(root);
      root.getDecorator<WebSocketServer>('websocketServer').on('connection', (socket, raw) => {
        const request = requests.get(raw);
        if (!request) return;
        const connection = new SubscriptionConnection(
          socket,
          schema,
          settings,
          authority,
          request.id,
          scopes,
          executions,
          options.owner ? AbortSignal.any([signal, options.owner]) : signal,
          (scope) => {
            assert.ok(active.size < 128);
            active.add(scope);
            void scope.completion.then(() => active.delete(scope));
          },
        );
        sockets.set(socket, connection);
        owners.push(connection);
      });
      root.register(async (child) => {
        child.addHook('onRequest', async (request, reply) => {
          if (
            request.headers.upgrade !== 'websocket' ||
            request.protocol !== 'https' ||
            request.headers.origin !== settings.subscriptions!.allowedOrigins[0] ||
            request.headers['sec-websocket-protocol'] !== 'graphql-transport-ws' ||
            request.headers.cookie ||
            request.raw.url?.includes('?')
          ) {
            await reply.code(403).send();
            return;
          }
          requests.set(request.raw, request);
        });
        await child.register(mercurius, {
          path: '/owned-subscriptions',
          schema,
          graphiql: false,
          cache: false,
          jit: 0,
          subscription: {
            fullWsTransport: false,
            async context(socket: WebSocket) {
              const connection = sockets.get(socket);
              assert.ok(connection);
              await connection.authenticate();
              const result = {},
                release = connections.bind(result, () => connection);
              void connection.completion.then(release);
              return result;
            },
          },
        });
        const connection = (context: object) => {
          const value = connections.get(context);
          assert.ok(value);
          return value;
        };
        child.graphql.addHook('preSubscriptionParsing', (_schema, _source, context: object, id) => {
          connection(context).parsed(String(id));
        });
        child.graphql.addHook(
          'preSubscriptionExecution',
          (_schema, _document, context: object, id) =>
            connection(context).start(context, String(id)),
        );
        child.graphql.addHook('onSubscriptionResolution', (execution, context: object, id) =>
          connection(context).resolution(execution, String(id)),
        );
        child.graphql.addHook('onSubscriptionEnd', (context: object, id) => {
          connection(context).stop(String(id));
        });
      });
    },
    async close() {
      for (const connection of owners) void connection.close();
    },
  };
  try {
    const f = await fixture(undefined, {
      tls: tls.tls,
      plugins: [probe],
      authorizeTenant: () => !revoked,
    });
    const wires = new Set<WebSocket>();
    return {
      f,
      ca: tls.ca,
      owners,
      active,
      allocated: () => allocated,
      closed: () => closed,
      revoke() {
        revoked = true;
      },
      publish(tenant: string, value: unknown) {
        for (const deliver of channels.get(tenant) ?? []) deliver(value);
      },
      async connect(tenant = 'tenant-a', init = true) {
        const socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/owned-subscriptions',
          'graphql-transport-ws',
          { ca: tls.ca, origin: 'https://portal.example.test' },
        );
        wires.add(socket);
        await once(socket, 'open');
        if (init) {
          const ack = Promise.race([
            once(socket, 'message'),
            once(socket, 'close').then(() => {
              throw new Error('Connection closed before native ACK');
            }),
          ]);
          socket.send(
            JSON.stringify({
              type: 'connection_init',
              payload: { authorization: await f.token(tenant) },
            }),
          );
          assert.deepEqual(JSON.parse(String((await ack)[0])), { type: 'connection_ack' });
        }
        return socket;
      },
      async close() {
        for (const socket of wires) socket.terminate();
        await f.close();
        await Promise.all(owners.map((connection) => connection.completion));
        await tls.close();
      },
    };
  } catch (error) {
    await tls.close();
    throw error;
  }
}
const start = (socket: WebSocket, id = 'one', tenantHint = 'tenant-b') =>
  socket.send(
    JSON.stringify({
      type: 'subscribe',
      id,
      payload: {
        query: 'subscription($tenant:String) { notice(tenantHint:$tenant) }',
        variables: { tenant: tenantHint },
      },
    }),
  );

test(
  'An actual WSS owner abort retires the live source and preserves the unrelated HTTP listener',
  { timeout: 10000 },
  async () => {
    const owner = new AbortController(),
      r = await runtime({ owner: owner.signal });
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => r.allocated() === 1 && r.active.size === 0);
      const closed = once(socket, 'close');
      owner.abort();
      await closed;
      await r.owners[0]!.completion;
      assert.equal(r.closed(), 1);
      assert.equal(r.active.size, 0);
      assert.equal(r.owners[0]!.stats().wireOpen, false);
      assert.equal(r.owners[0]!.stats().pendingWrites, 0);
      const response = await send(
        r.f.origin,
        { query: '{ ping }' },
        { ca: r.ca, headers: { authorization: await r.f.token() } },
      );
      assert.deepEqual(response.json(), { data: { ping: 'pong' } });
    } finally {
      await r.close();
    }
  },
);

test(
  'An already aborted WSS owner cannot acquire a source or retain a native connection',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ owner: AbortSignal.abort() });
    try {
      const socket = await r.connect('tenant-a', false);
      if (socket.readyState !== socket.CLOSED) await once(socket, 'close');
      await Promise.all(r.owners.map((connection) => connection.completion));
      assert.equal(r.allocated(), 0);
      assert.equal(r.active.size, 0);
      assert.equal(r.owners.length, 1);
      assert.equal(r.owners[0]!.stats().closed, true);
      assert.equal(r.owners[0]!.stats().wireOpen, false);
    } finally {
      await r.close();
    }
  },
);

test(
  'Actual native invalid UTF8 text closes only its WSS peer and confirms source retirement before another tenant proceeds',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => r.allocated() === 1 && r.active.size === 0);
      const closed = once(socket, 'close');
      socket.send(Buffer.from([0xff]), { binary: false });
      await closed;
      await r.owners[0]!.completion;
      assert.equal(r.closed(), 1);
      assert.equal(r.owners[0]!.stats().pendingWrites, 0);
      const healthy = await r.connect('tenant-b');
      start(healthy, 'two');
      await until(() => r.allocated() === 2 && r.active.size === 0);
      const answer = once(healthy, 'message');
      r.publish('tenant-b', 'healthy-after-native-error');
      assert.deepEqual(JSON.parse(String((await answer)[0])), {
        type: 'next',
        id: 'two',
        payload: { data: { notice: 'healthy-after-native-error' } },
      });
      assert.equal(r.owners[1]!.stats().failed, false);
    } finally {
      await r.close();
    }
  },
);
async function until(check: () => boolean) {
  for (let index = 0; index < 100 && !check(); index++) await delay(5);
  assert.ok(check());
}

test(
  'Owned native WSS delivers only verified tenant events and releases physical idle scopes before unsubscribe',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const a = await r.connect(),
        b = await r.connect('tenant-b');
      start(a);
      start(b, 'two', 'tenant-a');
      await until(() => r.allocated() === 2 && r.active.size === 0);
      const receivedA = once(a, 'message'),
        receivedB = once(b, 'message');
      r.publish('tenant-a', 'alpha');
      r.publish('tenant-b', 'beta');
      assert.deepEqual(JSON.parse(String((await receivedA)[0])), {
        type: 'next',
        id: 'one',
        payload: { data: { notice: 'alpha' } },
      });
      assert.deepEqual(JSON.parse(String((await receivedB)[0])), {
        type: 'next',
        id: 'two',
        payload: { data: { notice: 'beta' } },
      });
      const terminalA = once(a, 'message'),
        terminalB = once(b, 'message');
      a.send('{"type":"complete","id":"one"}');
      b.send('{"type":"complete","id":"two"}');
      assert.equal(JSON.parse(String((await terminalA)[0])).type, 'complete');
      assert.equal(JSON.parse(String((await terminalB)[0])).type, 'complete');
      await until(
        () => r.closed() === 2 && r.owners.every((owner) => owner.stats().activeOperations === 0),
      );
      assert.equal(r.active.size, 0);
      start(a);
      await until(() => r.allocated() === 3);
      const replacement = once(a, 'message');
      r.publish('tenant-a', 'replacement');
      assert.deepEqual(JSON.parse(String((await replacement)[0])), {
        type: 'next',
        id: 'one',
        payload: { data: { notice: 'replacement' } },
      });
      assert.equal(
        (
          await send(
            r.f.origin,
            { query: '{ ping }' },
            { ca: r.ca, headers: { authorization: await r.f.token() } },
          )
        ).status,
        200,
      );
    } finally {
      await r.close();
    }
  },
);

test(
  'Periodic verification closes a revoked idle connection through the actual tenant authority',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ revalidateMs: 30 });
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => r.allocated() === 1);
      const closed = once(socket, 'close');
      r.revoke();
      await closed;
      await r.owners[0]!.completion;
      assert.equal(r.closed(), 1);
      assert.equal(r.active.size, 0);
    } finally {
      await r.close();
    }
  },
);

test(
  'Starts before authenticated ACK and duplicate operation IDs never allocate additional sources',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const early = await r.connect('tenant-a', false),
        rejected = once(early, 'close');
      start(early);
      await rejected;
      assert.equal(r.allocated(), 0);
      const socket = await r.connect();
      start(socket);
      await until(() => r.allocated() === 1);
      const duplicate = once(socket, 'close');
      start(socket);
      await duplicate;
      await Promise.all(r.owners.map((owner) => owner.completion));
      assert.equal(r.allocated(), 1);
      assert.equal(r.closed(), 1);
    } finally {
      await r.close();
    }
  },
);

test(
  'Cancellation retains late source acquisition and its ID until the physical handle is retired',
  { timeout: 10000 },
  async () => {
    let provide!: (value: AsyncIterable<unknown>) => void,
      sourceSignal: AbortSignal | undefined,
      closes = 0;
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
        closes++;
        return { done: true, value: undefined };
      },
    };
    const r = await runtime({
      source(_parent, _args, context) {
        sourceSignal = context.signal;
        return pending;
      },
    });
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => sourceSignal !== undefined);
      socket.send('{"type":"complete","id":"one"}');
      await until(() => sourceSignal?.aborted === true);
      assert.equal(r.owners[0]!.stats().activeOperations, 1);
      let completed = false;
      void r.owners[0]!.close().then(() => {
        completed = true;
      });
      await delay(20);
      assert.equal(completed, false);
      provide(source);
      await r.owners[0]!.completion;
      assert.equal(closes, 1);
      assert.equal(r.active.size, 0);
      assert.equal(r.owners[0]!.stats().activeOperations, 0);
    } finally {
      provide(source);
      await r.close();
    }
  },
);

test(
  'The configured per-connection operation cap rejects excess work and closes all owned sources',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      const socket = await r.connect();
      start(socket, 'one');
      start(socket, 'two');
      await until(() => r.allocated() === 2);
      const closed = once(socket, 'close');
      start(socket, 'three');
      await closed;
      await r.owners[0]!.completion;
      assert.equal(r.allocated(), 2);
      assert.equal(r.closed(), 2);
      assert.equal(r.active.size, 0);
    } finally {
      await r.close();
    }
  },
);

test(
  'An unauthenticated idle wire expires without allocating any source',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ deadlineMs: 100 });
    try {
      const socket = await r.connect('tenant-a', false);
      await once(socket, 'close');
      await r.owners[0]!.completion;
      assert.equal(r.allocated(), 0);
      assert.equal(r.active.size, 0);
    } finally {
      await r.close();
    }
  },
);

test(
  'Provider retirement failures remain explicit after all physical work settles and close the connection safely',
  { timeout: 10000 },
  async () => {
    let entered = false;
    const r = await runtime({
      source(_parent, _args, context) {
        entered = true;
        let wake: ((value: IteratorResult<unknown>) => void) | undefined;
        context.signal.addEventListener('abort', () => wake?.({ done: true, value: undefined }), {
          once: true,
        });
        const iterator: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return this;
          },
          next() {
            if (context.signal.aborted) return Promise.resolve({ done: true, value: undefined });
            return new Promise((resolve) => {
              wake = resolve;
            });
          },
          async return() {
            throw new Error('Private broker cleanup detail');
          },
        };
        return iterator;
      },
    });
    try {
      const socket = await r.connect();
      start(socket);
      await until(() => entered);
      const closed = once(socket, 'close');
      socket.send('{"type":"complete","id":"one"}');
      const result = await closed;
      await r.owners[0]!.completion;
      assert.equal(r.owners[0]!.stats().failed, true);
      assert.equal(r.owners[0]!.stats().activeOperations, 0);
      assert.doesNotMatch(String(result[1]), /Private|broker cleanup detail/);
      assert.equal(r.active.size, 0);
    } finally {
      await r.close();
    }
  },
);

test(
  'A native source denial sends a safe error then closes without retaining unbounded native start contexts',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ authorize: () => false });
    try {
      const socket = await r.connect(),
        error = once(socket, 'message'),
        closed = once(socket, 'close');
      start(socket);
      const frame = JSON.parse(String((await error)[0]));
      assert.equal(frame.type, 'error');
      assert.equal(frame.payload[0].extensions.code, 'EK_GQL_FORBIDDEN');
      await closed;
      await r.owners[0]!.completion;
      assert.equal(r.allocated(), 0);
      assert.equal(r.active.size, 0);
      assert.equal(r.owners[0]!.stats().failed, false);
    } finally {
      await r.close();
    }
  },
);

test(
  'Native scalar serialization cannot send an event after its fresh execution deadline',
  { timeout: 10000 },
  async () => {
    const r = await runtime({
      deadlineMs: 300,
      source: async function* () {
        yield {
          valueOf() {
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 350);
            return 'late';
          },
        };
      },
    });
    try {
      const socket = await r.connect(),
        frames: string[] = [];
      socket.on('message', (frame) => frames.push(String(frame)));
      const closed = once(socket, 'close');
      start(socket);
      await closed;
      await r.owners[0]!.completion;
      assert.deepEqual(frames, []);
      assert.equal(r.active.size, 0);
    } finally {
      await r.close();
    }
  },
);
