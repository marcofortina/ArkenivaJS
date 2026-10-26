// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mkdtemp, chmod, readFile, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import { pathToFileURL } from 'node:url';
import { once } from 'node:events';
import { createApplication } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '@arkenivajs/socket';
import type { SocketPeer, SocketService } from '@arkenivajs/socket';

const execute = promisify(execFile),
  payload = Buffer.from([0, 1, 2, 255]);
const echo = async (peer: SocketPeer) => {
  for await (const bytes of peer.chunks()) await peer.send(bytes);
  await peer.end();
};
async function stream(client: net.Socket) {
  const timeout = setTimeout(
    () => client.destroy(new Error('The owned stream fixture deadline expired')),
    2000,
  );
  try {
    client.end(payload);
    const chunks: Buffer[] = [];
    for await (const bytes of client) chunks.push(bytes);
    const value = Buffer.concat(chunks);
    if (!value.equals(payload))
      throw new Error('The owned stream fixture received different bytes');
    return value.length;
  } finally {
    clearTimeout(timeout);
    client.destroy();
  }
}
/** Disposable real transports only; no public endpoints or persistent TLS material. */
export async function runSocketExample() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-example-')),
    path = join(directory, 'control.sock'),
    cert = join(directory, 'server.pem'),
    key = join(directory, 'server.key');
  await chmod(directory, 0o700);
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  try {
    await execute(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        key,
        '-out',
        cert,
      ],
      { timeout: 10000 },
    );
    await chmod(key, 0o600);
    app = await createApplication({
      service: { name: 'socket-example', version: '1.0.0', environment: 'test' },
      plugins: [
        socketPlugin({
          listeners: [
            { kind: 'tcp', options: { name: 'stream', port: 0 }, handler: echo },
            {
              kind: 'tls',
              options: {
                name: 'secure',
                port: 0,
                tls: { certificateFile: cert, privateKeyFile: key, minVersion: 'TLSv1.2' },
              },
              handler: echo,
            },
            { kind: 'unix', options: { name: 'local', path }, handler: echo },
            {
              kind: 'udp',
              options: { name: 'datagrams', family: 'udp4', port: 0 },
              handler: async (value, server) => {
                await server.reply(value, value.bytes);
              },
            },
          ],
        }),
      ],
    });
    await app.start();
    const sockets = app.resolve<SocketService>(SOCKET_CAPABILITY),
      binding = (name: string) => sockets.list().find((value) => value.name === name)!.binding!;
    const tcpBytes = await stream(
        net.connect({ host: '127.0.0.1', port: binding('stream').network!.port }),
      ),
      tlsBytes = await stream(
        tls.connect({
          host: '127.0.0.1',
          port: binding('secure').network!.port,
          servername: 'localhost',
          ca: await readFile(cert),
        }),
      ),
      unixBytes = await stream(net.connect(path));
    const client = dgram.createSocket('udp4');
    let udpBytes = 0;
    try {
      const response = once(client, 'message', { signal: AbortSignal.timeout(2000) });
      client.send(payload, binding('datagrams').network!.port, '127.0.0.1');
      const [bytes] = await response;
      if (!Buffer.from(bytes).equals(payload))
        throw new Error('The owned datagram fixture received different bytes');
      udpBytes = bytes.length;
    } finally {
      try {
        client.close();
      } catch {
        /* A timed-out fixture already closed its socket. */
      }
    }
    await app.stop();
    const privatePathRemoved = await lstat(path).then(
      () => false,
      (cause) => {
        if (cause.code === 'ENOENT') return true;
        throw cause;
      },
    );
    return Object.freeze({ tcpBytes, tlsBytes, unixBytes, udpBytes, privatePathRemoved });
  } finally {
    await app?.stop();
    await rm(directory, { recursive: true, force: true });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.stdout.write(JSON.stringify(await runSocketExample()) + '\n');
