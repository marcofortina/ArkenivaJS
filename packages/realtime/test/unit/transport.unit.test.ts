// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:http2';
import { once } from 'node:events';
import WebSocket from 'ws';
import { fixture } from '../fixture.js';
import { tlsFixture } from '../tls-fixture.js';

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
