// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, connect } from 'node:net';
import type { Socket, AddressInfo } from 'node:net';

/** A fixture-only loopback relay drops encrypted replies without terminating TLS or parsing MongoDB. */
export async function mongoNetworkProxy() {
  if (process.env.ARKENIVA_MONGODB_DISPOSABLE !== '1')
    throw new Error('The MongoDB relay requires a dedicated disposable fixture');
  const sockets = new Set<Socket>();
  let suppress = false,
    closing: Promise<void> | undefined;
  const server = createServer((client) => {
    const upstream = connect({ host: '127.0.0.1', port: 27018 });
    sockets.add(client);
    sockets.add(upstream);
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
      client.destroy();
    });
    client.pipe(upstream);
    upstream.on('data', (chunk: Buffer) => {
      if (!suppress && !client.destroyed && !client.write(chunk)) upstream.pause();
    });
    client.on('drain', () => upstream.resume());
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
    dropReplies() {
      suppress = true;
    },
    resumeReplies() {
      suppress = false;
    },
    close() {
      if (!closing)
        closing = new Promise<void>((resolve, reject) => {
          for (const socket of sockets) socket.destroy();
          server.close((error) => (error ? reject(error) : resolve()));
        });
      return closing;
    },
  };
}
