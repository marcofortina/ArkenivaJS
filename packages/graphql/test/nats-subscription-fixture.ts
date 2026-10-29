// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import type { RawData } from 'ws';
import { MessageType, parseMessage } from 'graphql-ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService, MessageBus } from '@arkenivajs/core';
import { messagingPlugin } from '@arkenivajs/messaging';
import { fixture, tlsFiles } from './fixture.js';
import { NatsPubSubFixture } from './nats-pubsub.js';

/** Protocol controls are not application deliveries; every other native frame remains visible. */
export function onSubscriptionFrame(socket: WebSocket, receive: (frame: RawData) => void) {
  const message = (frame: RawData) => {
    assert.ok(Buffer.isBuffer(frame));
    const parsed = parseMessage(frame.toString());
    if (parsed.type === MessageType.Ping || parsed.type === MessageType.Pong) return;
    assert.ok(
      parsed.type === MessageType.Next ||
        parsed.type === MessageType.Error ||
        parsed.type === MessageType.Complete,
    );
    receive(frame);
  };
  socket.on('message', message);
  return () => socket.off('message', message);
}
export function nextSubscriptionFrame(socket: WebSocket): Promise<readonly [RawData]> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      remove();
      socket.off('error', failed);
      socket.off('close', closed);
    };
    const failed = () => {
      cleanup();
      reject(new Error('The subscription transport failed before delivery'));
    };
    const closed = () => {
      cleanup();
      reject(new Error('The subscription transport closed before delivery'));
    };
    const remove = onSubscriptionFrame(socket, (frame) => {
      cleanup();
      resolve([frame]);
    });
    socket.once('error', failed);
    socket.once('close', closed);
  });
}

export async function natsSubscriptionFixture(
  namespace: string,
  issuer?: string,
  connectionStringEnv = 'ARKENIVA_NATS_URL',
) {
  assert.equal(process.env.ARKENIVA_NATS_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_NATS_URL);
  const tls = await tlsFiles(),
    adapter = new NatsPubSubFixture(namespace);
  const failures: string[] = [],
    wires = new Set<WebSocket>();
  try {
    const f = await fixture(
      {
        schema:
          'type Query { ping: String! } type Subscription { notice(tenantHint: String): String! }',
        resolvers: {
          Query: { ping: () => 'pong' },
          Subscription: {
            notice: {
              async subscribe(_parent, _args, context) {
                assert.ok(context.auth);
                const source = adapter.port.subscribe('notices', context.auth, {
                  signal: context.signal,
                });
                await adapter.ready();
                return source;
              },
              resolve: (parent) => parent,
            },
          },
        },
        security: {
          auth: { required: true, scopes: ['graphql:read'] },
          authorizeField: ({ context }) => !!context.auth,
        },
        subscriptions: {
          enabled: true,
          pubsub: adapter.port,
          maxConnections: 2,
          maxOperationsPerConnection: 2,
          maxQueuedEventsPerConnection: 4,
          revalidateIntervalMs: 100,
          allowedOrigins: ['https://portal.example.test'],
        },
      },
      {
        tls: tls.tls,
        ...(issuer ? { issuer } : {}),
        plugins: [
          messagingPlugin({
            connectionStringEnv,
            onError: async () => {
              failures.push('broker-operation-failed');
            },
          }),
        ],
        graphqlDependencies: ['messaging'],
      },
    );
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth);
    adapter.bind(authority, f.app.resolve<MessageBus>(COMPONENTS.messaging));
    return {
      f,
      adapter,
      failures,
      async connect(authorization: string) {
        const socket = new WebSocket(
          f.origin.replace('https:', 'wss:') + '/graphql',
          'graphql-transport-ws',
          { ca: tls.ca, origin: 'https://portal.example.test' },
        );
        wires.add(socket);
        await once(socket, 'open');
        socket.on('message', (frame) => {
          assert.ok(Buffer.isBuffer(frame));
          if (parseMessage(frame.toString()).type === MessageType.Ping)
            socket.send(JSON.stringify({ type: MessageType.Pong }));
        });
        const ack = Promise.race([
          once(socket, 'message'),
          once(socket, 'close').then(() => {
            throw new Error('The isolated broker connection closed before native ACK');
          }),
        ]);
        socket.send(JSON.stringify({ type: 'connection_init', payload: { authorization } }));
        assert.equal(JSON.parse(String((await ack)[0])).type, 'connection_ack');
        return socket;
      },
      async publish(authorization: string, value: string) {
        const identity = await authority.verifyBearer(authorization);
        await adapter.port.publish('notices', value, authority.tenantFrom(identity));
      },
      async close() {
        for (const socket of wires) socket.terminate();
        try {
          await f.close();
        } finally {
          try {
            await adapter.port.close();
          } finally {
            await tls.close();
          }
        }
      },
    };
  } catch (error) {
    try {
      await adapter.port.close();
    } finally {
      await tls.close();
    }
    throw error;
  }
}
