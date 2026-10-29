// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import mercurius from 'mercurius';
import type { MercuriusContext } from 'mercurius';
import { createClient } from 'graphql-ws';
import WebSocket from 'ws';
import type { WebSocketServer } from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { Plugin, AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { realtimePlugin } from '@arkenivajs/realtime';
import { subscriptionSocket } from '../../dist/subscription-socket.js';
import { fixture, tlsFiles, send } from '../fixture.js';

function nativeProbe(): Plugin {
  return {
    id: 'native-subscription-probe',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['api', 'security'],
    async init(context) {
      const root = context.require<ManagedApiServer>(COMPONENTS.api).native();
      const auth = context.require<AuthService>(COMPONENTS.auth);
      await subscriptionSocket(root, 2097152);
      root.register(async (child) => {
        child.addHook('onRequest', async (request, reply) => {
          if (request.headers.upgrade?.toLowerCase() !== 'websocket') await reply.code(404).send();
        });
        await child.register(mercurius, {
          path: '/native-subscriptions',
          schema: 'type Query { ping: String } type Subscription { once: String! }',
          resolvers: {
            Subscription: {
              once: {
                async *subscribe(_parent: unknown, _args: unknown, context: MercuriusContext) {
                  const principal = (
                    context as MercuriusContext & { principal: VerifiedTenantContext }
                  ).principal;
                  assert.equal(auth.tenantFrom(principal.identity), principal);
                  yield { once: principal.tenantId };
                },
              },
            },
          },
          subscription: {
            async onConnect(data: { payload: { authorization?: string } }) {
              try {
                const identity = await auth.verifyBearer(data.payload.authorization);
                return { principal: auth.tenantFrom(identity) };
              } catch {
                return false;
              }
            },
          },
          graphiql: false,
          jit: 0,
        });
      });
    },
    close() {},
  };
}
function echo(): Plugin {
  return realtimePlugin({
    routes: [{ kind: 'websocket', path: '/shared-echo', handlerKey: 'echo', policyKey: 'bounded' }],
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
  });
}

for (const order of ['native-first', 'realtime-first'] as const)
  test(
    `Native GraphQL and realtime share one WSS upgrade dispatcher with ${order} registration`,
    { timeout: 10000 },
    async () => {
      const tls = await tlsFiles();
      const native = nativeProbe(),
        realtime = echo();
      const plugins =
        order === 'native-first'
          ? [native, { ...realtime, dependencies: [...(realtime.dependencies ?? []), native.id] }]
          : [realtime, { ...native, dependencies: [...(native.dependencies ?? []), realtime.id] }];
      const f = await fixture(undefined, { tls: tls.tls, plugins });
      let wire: WebSocket | undefined;
      let client: ReturnType<typeof createClient> | undefined;
      try {
        const root = f.api.native();
        assert.equal(
          root.server.listenerCount('upgrade'),
          1,
          'The shared HTTP listener must have exactly one native WS dispatcher',
        );
        assert.equal(root.hasDecorator('websocketServer'), true);
        const socketOptions = root.getDecorator<WebSocketServer>('websocketServer').options;
        assert.equal(socketOptions.perMessageDeflate, false);
        assert.equal(socketOptions.maxPayload, 2097152);
        class TrustedSocket extends WebSocket {
          constructor(url: string, protocols?: string | string[]) {
            super(url, protocols, { ca: tls.ca });
          }
        }
        wire = new WebSocket(f.origin.replace('https:', 'wss:') + '/shared-echo', {
          ca: tls.ca,
          headers: { authorization: await f.token() },
        });
        await once(wire, 'open');
        const echoed = once(wire, 'message');
        const message = {
          channel: 'shared',
          payload: Buffer.from('independent-protocol').toString('base64url'),
        };
        wire.send(JSON.stringify(message));
        assert.deepEqual(JSON.parse(String((await echoed)[0])), message);
        client = createClient({
          url: f.origin.replace('https:', 'wss:') + '/native-subscriptions',
          webSocketImpl: TrustedSocket,
          connectionParams: { authorization: await f.token() },
          retryAttempts: 0,
        });
        const values = client.iterate({ query: 'subscription { once }' });
        assert.deepEqual((await values.next()).value, { data: { once: 'tenant-a' } });
        await values.return?.();
        const routeClosed = once(wire, 'close');
        wire.send(JSON.stringify({ channel: 'oversized', payload: 'x'.repeat(1500) }));
        await routeClosed;
        const query = await send(
          f.origin,
          { query: '{ ping }' },
          { ca: tls.ca, headers: { authorization: await f.token() } },
        );
        assert.equal(query.status, 200);
        assert.deepEqual(query.json(), { data: { ping: 'pong' } });
      } finally {
        await client?.dispose();
        wire?.terminate();
        await f.close();
        await tls.close();
      }
    },
  );
