// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, connect } from 'node:net';
import type { AddressInfo, Socket } from 'node:net';

/** Relay only the authorized loopback fixture; TLS bytes are never parsed or modified. */
export async function natsNetworkProxy() {
  if (process.env.ARKENIVA_NATS_DISPOSABLE !== '1' || !process.env.ARKENIVA_NATS_URL)
    throw new Error('The NATS relay requires a disposable fixture');
  const url = new URL(process.env.ARKENIVA_NATS_URL);
  if (!['localhost', '127.0.0.1'].includes(url.hostname))
    throw new Error('The NATS relay only accepts a loopback fixture');
  const sockets = new Set<Socket>(),
    replies = new Set<Socket>();
  let blocked = false,
    paused = false;
  const server = createServer((client) => {
    if (blocked) {
      client.destroy();
      return;
    }
    const upstream = connect({ host: '127.0.0.1', port: Number(url.port) });
    sockets.add(client);
    sockets.add(upstream);
    replies.add(upstream);
    const destroy = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('error', destroy);
    upstream.on('error', destroy);
    client.on('close', () => {
      sockets.delete(client);
      upstream.destroy();
    });
    upstream.on('close', () => {
      sockets.delete(upstream);
      replies.delete(upstream);
      client.destroy();
    });
    client.pipe(upstream);
    upstream.pipe(client);
    if (paused) upstream.pause();
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  return {
    port: (server.address() as AddressInfo).port,
    pauseReplies() {
      paused = true;
      for (const socket of replies) socket.pause();
    },
    resumeReplies() {
      paused = false;
      for (const socket of replies) socket.resume();
    },
    disconnect() {
      blocked = true;
      for (const socket of sockets) socket.destroy();
    },
    resume() {
      blocked = false;
    },
    async close() {
      blocked = true;
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((cause) => (cause ? reject(cause) : resolve())),
      );
    },
  };
}
