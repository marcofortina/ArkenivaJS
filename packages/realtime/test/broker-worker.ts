// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { once } from 'node:events';
import WebSocket from 'ws';
import { messagingPlugin } from '@arkenivajs/messaging';
import { redisPlugin } from '@arkenivajs/database-redis';
import { fixture } from './fixture.js';

interface Start {
  provider: 'redis' | 'nats';
  issuer: string;
  authorization: string;
  otherAuthorization: string;
}
const sockets: WebSocket[] = [];
let app: Awaited<ReturnType<typeof fixture>> | undefined;
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  for (const socket of sockets) socket.terminate();
  await app?.close();
  process.disconnect?.();
}
process.once('disconnect', () => {
  void close();
});
process.once('message', (input: Start) => {
  void (async () => {
    const redis = input.provider === 'redis';
    app = await fixture(
      { pubsub: { provider: input.provider, connectionName: redis ? 'shared' : 'messaging' } },
      undefined,
      [
        redis
          ? redisPlugin()
          : messagingPlugin({
              connectionStringEnv: 'ARKENIVA_NATS_URL',
              onError: async () => {
                process.send?.({ kind: 'failure' });
              },
            }),
      ],
      {
        issuer: input.issuer,
        ...(redis
          ? {
              databases: { shared: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
            }
          : {}),
      },
    );
    for (const [tenant, authorization] of [
      ['a', input.authorization],
      ['b', input.otherAuthorization],
    ] as const) {
      const socket = new WebSocket(app.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization },
      });
      sockets.push(socket);
      socket.on('message', (frame) =>
        process.send?.({ kind: 'frame', tenant, frame: String(frame) }),
      );
      await once(socket, 'open');
    }
    process.send?.({ kind: 'ready' });
    process.once('message', () => {
      void close().catch(() => {
        process.exitCode = 1;
      });
    });
  })().catch(async () => {
    process.send?.({ kind: 'failure' });
    process.exitCode = 1;
    await close();
  });
});
