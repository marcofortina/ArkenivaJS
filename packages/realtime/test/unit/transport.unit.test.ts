// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:http2';
import { once } from 'node:events';
import WebSocket from 'ws';
import type { WebSocketServer } from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { fixture } from '../fixture.js';
import { tlsFixture } from '../tls-fixture.js';

for (const binaryType of ['arraybuffer', 'fragments'] as const)
  test(
    `Actual native ${binaryType} fragmented WebSocket frames retain bytes and reject noncanonical base64url`,
    { timeout: 10000 },
    async () => {
      const nativeShape: Plugin = {
        id: 'native-frame-shape',
        version: '1.0.0',
        capabilities: new Set(),
        dependencies: ['api', 'realtime'],
        init(context) {
          const server = context.require<ManagedApiServer>(COMPONENTS.api).native() as ReturnType<
            ManagedApiServer['native']
          > & { websocketServer: WebSocketServer };
          server.websocketServer.on('connection', (socket) => {
            socket.binaryType = binaryType;
          });
        },
        close() {},
      };
      const f = await fixture({}, undefined, [nativeShape]);
      const sockets: WebSocket[] = [];
      try {
        const authorization = await f.token();
        const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
          headers: { authorization },
        });
        sockets.push(socket);
        await once(socket, 'open');
        const message = {
          channel: 'updates',
          payload: Buffer.from([0, 255, 128, 1]).toString('base64url'),
          id: 'fragment_1',
        };
        const bytes = Buffer.from(JSON.stringify(message)),
          split = Math.floor(bytes.length / 2);
        const answer = once(socket, 'message');
        socket.send(bytes.subarray(0, split), { binary: true, fin: false });
        socket.send(bytes.subarray(split), { binary: true, fin: true });
        assert.deepEqual(JSON.parse(String((await answer)[0])), message);
        const closed = once(socket, 'close');
        socket.close();
        await closed;
        const invalid = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
          headers: { authorization },
        });
        sockets.push(invalid);
        await once(invalid, 'open');
        let received = 0;
        invalid.on('message', () => {
          received++;
        });
        const denied = once(invalid, 'close');
        invalid.send('{"channel":"updates","payload":"AB"}', { binary: true });
        await denied;
        assert.equal(received, 0);
      } finally {
        for (const socket of sockets) socket.terminate();
        await f.close();
      }
    },
  );

test(
  'Actual verified WSS and direct HTTP2 SSE share the framework HTTPS listener',
  { timeout: 10000 },
  async () => {
    const tls = await tlsFixture(),
      f = await fixture({}, { tls: tls.files, http2: true });
    const client = connect(f.origin, { ca: tls.ca, rejectUnauthorized: true });
    let socket: WebSocket | undefined;
    try {
      await once(client, 'connect');
      const authorization = await f.token();
      const stream = client.request({
        ':path': '/events',
        accept: 'text/event-stream',
        authorization,
      });
      const status = new Promise<number>((resolve) =>
        stream.once('response', (headers) => resolve(Number(headers[':status']))),
      );
      const chunks: Buffer[] = [];
      stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      stream.end();
      await once(stream, 'end');
      assert.equal(await status, 200, Buffer.concat(chunks).toString('utf8'));
      assert.match(Buffer.concat(chunks).toString('utf8'), /id: tenant-a_1/);
      socket = new WebSocket(f.origin.replace('https:', 'wss:') + '/socket', {
        ca: tls.ca,
        rejectUnauthorized: true,
        headers: { authorization },
      });
      await once(socket, 'open');
      const echoed = once(socket, 'message');
      socket.send('{"channel":"secure","payload":"aGk"}');
      const [message] = await echoed;
      assert.equal(JSON.parse(String(message)).payload, 'aGk');
    } finally {
      socket?.terminate();
      client.destroy();
      await f.close();
      await tls.close();
    }
  },
);
