// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService, Identity, MfaAssurance, VerifiedTenantContext } from '@arkenivajs/core';
import { realtimePlugin } from '@arkenivajs/realtime';
import type { GraphqlPluginSettings, GraphqlSubscriptionPubSub } from '../../dist/index.js';
import { fixture, tlsFiles, send } from '../fixture.js';

function settings(
  options: { allowGet?: boolean; deadlineMs?: number; assurance?: MfaAssurance } = {},
) {
  let authority: AuthService | undefined,
    effects = 0,
    acquired = 0,
    retired = 0;
  const channels = new Map<string, Set<(value: unknown) => void>>();
  const handles = new Set<() => void>();
  const verify = (tenant: VerifiedTenantContext) => {
    assert.ok(authority);
    assert.equal(authority.tenantFrom(tenant.identity), tenant);
  };
  const pubsub: GraphqlSubscriptionPubSub = {
    subscribe(topic, tenant, options) {
      verify(tenant);
      assert.equal(topic, 'notices');
      acquired++;
      const listeners = channels.get(tenant.tenantId) ?? new Set<(value: unknown) => void>();
      channels.set(tenant.tenantId, listeners);
      let wake: ((value: IteratorResult<unknown>) => void) | undefined,
        closed = false;
      const queue: unknown[] = [];
      const publish = (value: unknown) => {
        if (closed) return;
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
        if (closed) return;
        closed = true;
        retired++;
        listeners.delete(publish);
        handles.delete(stop);
        options?.signal?.removeEventListener('abort', stop);
        wake?.({ done: true, value: undefined });
        wake = undefined;
      };
      listeners.add(publish);
      handles.add(stop);
      options?.signal?.addEventListener('abort', stop, { once: true });
      const source: AsyncIterableIterator<unknown> = {
        [Symbol.asyncIterator]() {
          return this;
        },
        next() {
          if (closed) return Promise.resolve({ done: true, value: undefined });
          if (queue.length) return Promise.resolve({ done: false, value: queue.shift() });
          return new Promise((resolve) => {
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
    async publish(topic, payload, tenant) {
      verify(tenant);
      assert.equal(topic, 'notices');
      for (const publish of channels.get(tenant.tenantId) ?? []) publish(payload);
    },
    async close() {
      for (const stop of handles) stop();
    },
  };
  const value: GraphqlPluginSettings = {
    schema:
      'type Query { ping: String! private: String } type Mutation { update: Boolean! } type Subscription { notice(tenantHint: String): String! }',
    resolvers: {
      Query: {
        ping: () => 'pong',
        private: () => {
          effects++;
          return 'private';
        },
      },
      Mutation: {
        update: () => {
          effects++;
          return true;
        },
      },
      Subscription: {
        notice: {
          subscribe(_parent, _args, context) {
            assert.ok(context.auth);
            return pubsub.subscribe('notices', context.auth, { signal: context.signal });
          },
          resolve: (parent) => parent,
        },
      },
    },
    security: {
      auth: {
        required: true,
        scopes: ['graphql:read'],
        ...(options.assurance ? { assurance: options.assurance } : {}),
      },
      authorizeField: ({ field }) => field.fieldName !== 'private',
      ...(options.allowGet ? { allowGetQueries: true } : {}),
      ...(options.deadlineMs ? { limits: { maxOperationMs: options.deadlineMs } } : {}),
    },
    subscriptions: {
      enabled: true,
      pubsub,
      maxConnections: 2,
      maxOperationsPerConnection: 2,
      maxQueuedEventsPerConnection: 4,
      revalidateIntervalMs: 50,
      allowedOrigins: ['https://portal.example.test'],
    },
  };
  return {
    value,
    pubsub,
    effects: () => effects,
    acquired: () => acquired,
    retired: () => retired,
    use(auth: AuthService) {
      authority = auth;
    },
  };
}
async function runtime(
  options: {
    allowGet?: boolean;
    http2?: boolean;
    realtimeOrder?: 'before' | 'after';
    deadlineMs?: number;
    assurance?: MfaAssurance;
    assuranceResolver?: (identity: Identity) => MfaAssurance;
  } = {},
) {
  const tls = await tlsFiles(),
    config = settings(options);
  try {
    const realtime = options.realtimeOrder
      ? realtimePlugin({
          routes: [
            { kind: 'websocket', path: '/public-echo', handlerKey: 'echo', policyKey: 'bounded' },
          ],
          websocketHandlers: {
            async echo(session) {
              for await (const message of session.receive()) await session.send(message);
            },
          },
          sseSources: {},
          policies: {
            bounded: {
              requireAuth: true,
              maxConnectionsPerTenant: 2,
              maxMessageBytes: 1024,
              maxBufferBytes: 4096,
              heartbeatMs: 100,
              idleTimeoutMs: 5000,
            },
          },
          policy: { maxConcurrent: 4, timeoutMs: 1000 },
        })
      : undefined;
    const f = await fixture(config.value, {
      tls: tls.tls,
      ...(options.assuranceResolver ? { assuranceResolver: options.assuranceResolver } : {}),
      ...(options.http2 ? { http2: true } : {}),
      ...(realtime
        ? {
            plugins: [
              options.realtimeOrder === 'after'
                ? { ...realtime, dependencies: [...(realtime.dependencies ?? []), 'graphql'] }
                : realtime,
            ],
          }
        : {}),
      ...(options.realtimeOrder === 'before' ? { graphqlDependencies: ['realtime'] } : {}),
    });
    const auth = f.app.resolve<AuthService>(COMPONENTS.auth);
    config.use(auth);
    const wires = new Set<WebSocket>();
    return {
      f,
      config,
      tls,
      auth,
      async connect(tenant = 'tenant-a', assertion?: string) {
        const socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          { ca: tls.ca, origin: 'https://portal.example.test' },
        );
        wires.add(socket);
        await once(socket, 'open');
        const ack = Promise.race([
          once(socket, 'message'),
          once(socket, 'close').then(() => {
            throw new Error('Native connection closed before ACK');
          }),
        ]);
        socket.send(
          JSON.stringify({
            type: 'connection_init',
            payload: { authorization: assertion ?? (await f.token(tenant)) },
          }),
        );
        assert.deepEqual(JSON.parse(String((await ack)[0])), { type: 'connection_ack' });
        return socket;
      },
      async publish(tenant: string, value: unknown) {
        const identity = await auth.verifyBearer(await f.token(tenant));
        await config.pubsub.publish('notices', value, auth.tenantFrom(identity));
      },
      async close() {
        for (const wire of wires) wire.terminate();
        try {
          await f.close();
        } finally {
          await config.pubsub.close();
          await tls.close();
        }
      },
    };
  } catch (error) {
    await config.pubsub.close();
    await tls.close();
    throw error;
  }
}
async function until(check: () => boolean) {
  for (let index = 0; index < 200 && !check(); index++) await delay(5);
  assert.ok(check());
}
const start = (socket: WebSocket, id: string) =>
  socket.send(
    JSON.stringify({
      type: 'subscribe',
      id,
      payload: { query: 'subscription { notice(tenantHint:"spoofed") }' },
    }),
  );

for (const failure of ['downgrade', 'provider-error'] as const)
  test(
    `Public WSS enforces trusted MFA assurance at admission and after ${failure} without affecting another tenant`,
    { timeout: 10000 },
    async () => {
      let strength: MfaAssurance = 'single-factor',
        unavailable = false;
      const r = await runtime({
        assurance: 'mfa',
        deadlineMs: 500,
        assuranceResolver(identity) {
          // Assurance belongs to trusted issuer policy, never a client-provided MFA claim.
          if (identity.claims.tenant_id === 'tenant-b') return 'phishing-resistant';
          if (unavailable) throw new Error('Private assurance authority failure detail');
          return strength;
        },
      });
      const collect = (socket: WebSocket) => {
        const values: unknown[] = [];
        socket.on('message', (input) => {
          const frame = JSON.parse(String(input));
          if (frame.type === 'ping') socket.send('{"type":"pong"}');
          else if (frame.type === 'next') values.push(frame);
        });
        return values;
      };
      try {
        await assert.rejects(r.connect());
        await until(() => r.f.service.stats().activeOperations === 0);
        assert.equal(r.config.acquired(), 0);
        strength = 'mfa';
        const first = await r.connect(),
          second = await r.connect('tenant-b');
        const a = collect(first),
          b = collect(second);
        start(first, 'a');
        start(second, 'b');
        await until(() => r.config.acquired() === 2);
        await r.publish('tenant-a', 'authorized');
        await until(() => a.length === 1);
        assert.deepEqual(a, [
          { type: 'next', id: 'a', payload: { data: { notice: 'authorized' } } },
        ]);
        assert.deepEqual(b, []);
        const principal = r.auth.tenantFrom(await r.auth.verifyBearer(await r.f.token()));
        const closed = once(first, 'close');
        if (failure === 'downgrade') strength = 'single-factor';
        else unavailable = true;
        // An already authenticated publisher cannot bypass the subscriber's fresh assurance check.
        await r.config.pubsub.publish('notices', 'must-not-be-delivered', principal);
        await closed;
        await until(
          () => r.config.retired() === 1 && r.f.service.stats().activeSubscriptions === 1,
        );
        const identity = await r.auth.verifyBearer(await r.f.token('tenant-b'));
        const tenant = r.auth.tenantFrom(identity);
        await r.config.pubsub.publish('notices', 'other-tenant', tenant);
        await until(() => b.length === 1);
        assert.deepEqual(b, [
          { type: 'next', id: 'b', payload: { data: { notice: 'other-tenant' } } },
        ]);
        assert.equal(a.length, 1);
        assert.equal(r.f.service.health().subscriptionsReady, true);
        assert.equal(r.config.acquired(), 2);
        unavailable = false;
        strength = 'mfa';
        const recovered = await r.connect();
        const recoveredFrames = collect(recovered);
        start(recovered, 'recovered');
        await until(() => r.config.acquired() === 3);
        await r.publish('tenant-a', 'recovered');
        await until(() => recoveredFrames.length === 1);
        assert.deepEqual(recoveredFrames, [
          { type: 'next', id: 'recovered', payload: { data: { notice: 'recovered' } } },
        ]);
        assert.equal(a.length, 1);
        assert.equal(b.length, 1);
        assert.doesNotMatch(r.f.logs(), /Bearer |Private assurance authority failure detail/);
      } finally {
        await r.close();
      }
      assert.equal(r.config.retired(), r.config.acquired());
      assert.equal(r.f.service.stats().activeSubscriptions, 0);
    },
  );

test(
  'Public WSS rejects genuinely signed expired or unscoped credentials before source allocation and admits a later valid owner',
  { timeout: 10000 },
  async () => {
    const r = await runtime();
    try {
      for (const token of [
        await r.f.token('tenant-a', 'other:scope'),
        await r.f.token('tenant-a', 'graphql:read', Math.floor(Date.now() / 1000) - 30),
      ]) {
        await assert.rejects(r.connect('tenant-a', token));
        await until(() => r.f.service.stats().activeOperations === 0);
        assert.equal(r.config.acquired(), 0);
        assert.ok(!r.f.logs().includes(token));
      }
      const valid = await r.connect();
      start(valid, 'accepted');
      await until(() => r.config.acquired() === 1);
      const event = once(valid, 'message');
      await r.publish('tenant-a', 'valid-after-denial');
      assert.deepEqual(JSON.parse(String((await event)[0])), {
        type: 'next',
        id: 'accepted',
        payload: { data: { notice: 'valid-after-denial' } },
      });
      assert.equal(r.f.service.health().subscriptionsReady, true);
    } finally {
      await r.close();
    }
  },
);

test(
  'Public WSS heartbeat responses cannot extend an expired signed credential or retain its source',
  { timeout: 20000 },
  async () => {
    const r = await runtime({ deadlineMs: 500 });
    try {
      const expiresAt = Math.floor(Date.now() / 1000) + 3,
        token = await r.f.token('tenant-a', 'graphql:read', expiresAt),
        socket = await r.connect('tenant-a', token);
      let heartbeats = 0;
      socket.on('message', (raw) => {
        if (JSON.parse(String(raw)).type === 'ping') {
          heartbeats++;
          socket.send('{"type":"pong"}');
        }
      });
      const first = new Promise<unknown>((resolve) =>
        socket.on('message', (raw) => {
          const message = JSON.parse(String(raw));
          if (message.type === 'next') resolve(message);
        }),
      );
      start(socket, 'expiring');
      await until(() => r.config.acquired() === 1);
      await r.publish('tenant-a', 'before-expiry');
      assert.deepEqual(await first, {
        type: 'next',
        id: 'expiring',
        payload: { data: { notice: 'before-expiry' } },
      });
      // Verification retains the authentication provider's configured clock tolerance.
      await once(socket, 'close');
      assert.ok(Date.now() >= expiresAt * 1000);
      assert.ok(heartbeats > 0);
      await until(() => r.config.retired() === 1 && r.f.service.stats().activeSubscriptions === 0);
      assert.equal(r.f.service.stats().activeOperations, 0);
      assert.equal(r.f.service.health().subscriptionsReady, true);
      const denied = await send(
        r.f.origin,
        { query: '{ ping }' },
        {
          ca: r.tls.ca,
          headers: { authorization: token },
        },
      );
      assert.equal(denied.status, 401);
      const healthy = await r.connect('tenant-b'),
        later = new Promise<unknown>((resolve) =>
          healthy.on('message', (raw) => {
            const message = JSON.parse(String(raw));
            if (message.type === 'next') resolve(message);
          }),
        );
      start(healthy, 'other-owner');
      await until(() => r.config.acquired() === 2);
      await r.publish('tenant-b', 'after-expiry');
      assert.deepEqual(await later, {
        type: 'next',
        id: 'other-owner',
        payload: { data: { notice: 'after-expiry' } },
      });
      assert.ok(!r.f.logs().includes(token));
    } finally {
      await r.close();
    }
  },
);

for (const http2 of [false, true])
  test(
    `Public GraphQL plugin shares guarded HTTP and tenant-bound WSS on one listener with HTTP/2 ${http2}`,
    { timeout: 10000 },
    async () => {
      const r = await runtime({ http2 });
      try {
        assert.equal(r.f.api.native().server.listenerCount('upgrade'), 1);
        assert.equal(r.f.service.health().subscriptionsReady, true);
        const a = await r.connect(),
          b = await r.connect('tenant-b');
        start(a, 'a');
        start(b, 'b');
        await until(() => r.config.acquired() === 2);
        const receivedA = once(a, 'message'),
          receivedB = once(b, 'message');
        await r.publish('tenant-a', 'alpha');
        await r.publish('tenant-b', 'beta');
        assert.deepEqual(JSON.parse(String((await receivedA)[0])), {
          type: 'next',
          id: 'a',
          payload: { data: { notice: 'alpha' } },
        });
        assert.deepEqual(JSON.parse(String((await receivedB)[0])), {
          type: 'next',
          id: 'b',
          payload: { data: { notice: 'beta' } },
        });
        assert.equal(r.f.service.stats().activeSubscriptions, 2);
        const authorization = await r.f.token();
        const post = await send(
          r.f.origin,
          { query: '{ ping private }' },
          { ca: r.tls.ca, headers: { authorization } },
        );
        assert.deepEqual(post.json().data, { ping: 'pong', private: null });
        assert.match(post.body, /EK_GQL_FORBIDDEN/);
        assert.equal(r.config.effects(), 0);
        for (const method of ['GET', 'QUERY', 'HEAD']) {
          const denied = await send(r.f.origin, undefined, {
            ca: r.tls.ca,
            method,
            path: '/graphql?query=%7Bping%7D',
            headers: { authorization },
          });
          assert.ok(denied.status >= 400, method + ':' + denied.body);
        }
        const malformed = await send(
          r.f.origin,
          { query: { kind: 'Document', definitions: [] } },
          { ca: r.tls.ca, headers: { authorization } },
        );
        assert.equal(malformed.status, 400);
        const terminalA = once(a, 'message'),
          terminalB = once(b, 'message');
        a.send('{"type":"complete","id":"a"}');
        b.send('{"type":"complete","id":"b"}');
        await Promise.all([terminalA, terminalB]);
        await until(
          () => r.config.retired() === 2 && r.f.service.stats().activeSubscriptions === 0,
        );
      } finally {
        await r.close();
      }
    },
  );

test(
  'The public subscription route preserves opt-in GET queries and rejects GET mutation and WS query execution',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ allowGet: true });
    try {
      const authorization = await r.f.token();
      assert.deepEqual(
        (
          await send(r.f.origin, undefined, {
            ca: r.tls.ca,
            method: 'GET',
            path: '/graphql?query=%7Bping%7D',
            headers: { authorization },
          })
        ).json(),
        { data: { ping: 'pong' } },
      );
      const mutation = await send(r.f.origin, undefined, {
        ca: r.tls.ca,
        method: 'GET',
        path: '/graphql?query=mutation%7Bupdate%7D',
        headers: { authorization },
      });
      assert.equal(mutation.status, 400);
      assert.equal(r.config.effects(), 0);
      const socket = await r.connect(),
        closed = once(socket, 'close');
      socket.send('{"type":"subscribe","id":"one","payload":{"query":"{ping}"}}');
      await closed;
      assert.equal(r.config.acquired(), 0);
      assert.equal(r.config.effects(), 0);
    } finally {
      await r.close();
    }
  },
);

test(
  'Unclassified development providers and plaintext subscription startup fail closed before listening',
  { timeout: 10000 },
  async () => {
    const tls = await tlsFiles();
    try {
      await assert.rejects(
        fixture(settings().value, { tls: tls.tls, environment: 'development' }),
        (error: unknown) =>
          error instanceof KitError &&
          error.code === 'EK_PLUGIN_FAILED' &&
          error.cause instanceof KitError &&
          error.cause.code === 'EK_GQL_CONFIG',
      );
      await assert.rejects(
        fixture(settings().value),
        (error: unknown) => error instanceof KitError && error.code === 'EK_PLUGIN_FAILED',
      );
    } finally {
      await tls.close();
    }
  },
);

for (const realtimeOrder of ['before', 'after'] as const)
  test(
    `Public GraphQL and Realtime retain one native dispatcher with Realtime initialized ${realtimeOrder} GraphQL`,
    { timeout: 10000 },
    async () => {
      const r = await runtime({ realtimeOrder });
      let echo: WebSocket | undefined;
      try {
        assert.equal(r.f.api.native().server.listenerCount('upgrade'), 1);
        echo = new WebSocket(r.f.origin.replace('https:', 'wss:') + '/public-echo', {
          ca: r.tls.ca,
          headers: { authorization: await r.f.token() },
        });
        await once(echo, 'open');
        const echoed = once(echo, 'message'),
          message = {
            channel: 'shared',
            payload: Buffer.from('independent-route').toString('base64url'),
          };
        echo.send(JSON.stringify(message));
        assert.deepEqual(JSON.parse(String((await echoed)[0])), message);
        const socket = await r.connect();
        start(socket, 'one');
        await until(() => r.config.acquired() === 1);
        const received = once(socket, 'message');
        await r.publish('tenant-a', 'event');
        assert.deepEqual(JSON.parse(String((await received)[0])), {
          type: 'next',
          id: 'one',
          payload: { data: { notice: 'event' } },
        });
        const closed = once(echo, 'close');
        echo.send(JSON.stringify({ channel: 'oversized', payload: 'x'.repeat(1500) }));
        await closed;
        const next = once(socket, 'message');
        await r.publish('tenant-a', 'still-owned');
        assert.deepEqual(JSON.parse(String((await next)[0])), {
          type: 'next',
          id: 'one',
          payload: { data: { notice: 'still-owned' } },
        });
        assert.equal(r.f.service.stats().activeSubscriptions, 1);
      } finally {
        echo?.terminate();
        await r.close();
      }
    },
  );

test(
  'Public native protocol heartbeats retain responsive clients and retire a missing pong without granting identity',
  { timeout: 10000 },
  async () => {
    const r = await runtime({ deadlineMs: 250 });
    let untrusted: WebSocket | undefined;
    try {
      const responsive = await r.connect();
      let pings = 0;
      responsive.on('message', (frame) => {
        const message = JSON.parse(String(frame));
        if (message.type === 'ping') {
          pings++;
          responsive.send('{"type":"pong"}');
        }
      });
      const unresponsive = await r.connect(),
        closed = once(unresponsive, 'close');
      await closed;
      assert.ok(pings >= 1);
      assert.equal(responsive.readyState, WebSocket.OPEN);
      assert.equal(r.config.acquired(), 0);
      assert.equal(r.f.service.health().subscriptionsReady, true);
      untrusted = new WebSocket(
        r.f.origin.replace('https:', 'wss:') + '/graphql',
        'graphql-transport-ws',
        { ca: r.tls.ca, origin: 'https://portal.example.test' },
      );
      await once(untrusted, 'open');
      const rejected = once(untrusted, 'close');
      untrusted.send('{"type":"pong"}');
      start(untrusted, 'forged');
      await rejected;
      assert.equal(r.config.acquired(), 0);
      const result = new Promise<unknown>((resolve) =>
        responsive.on('message', (frame) => {
          const message = JSON.parse(String(frame));
          if (message.type === 'next') resolve(message);
        }),
      );
      start(responsive, 'live');
      await until(() => r.config.acquired() === 1);
      await r.publish('tenant-a', 'still-authorized');
      assert.deepEqual(await result, {
        type: 'next',
        id: 'live',
        payload: { data: { notice: 'still-authorized' } },
      });
    } finally {
      untrusted?.terminate();
      await r.close();
    }
  },
);
