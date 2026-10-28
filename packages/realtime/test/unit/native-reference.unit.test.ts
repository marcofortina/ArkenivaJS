// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, get } from 'node:http';
import { once } from 'node:events';
import Fastify from 'fastify';
import { fastifySSE } from '@fastify/sse';

test(
  'Native SSE wire framing matches a bounded Node HTTP reference for Unicode, multiline and empty text',
  { timeout: 5000 },
  async () => {
    const events = [
      { id: 'event_1', event: 'update', data: 'Unicode: π 😀' },
      { id: 'event_2', event: 'update', data: 'first\nsecond\n' },
      { id: 'event_3', event: 'empty', data: '' },
    ];
    const reference = createServer(async (_request, response) => {
      response.setHeader('content-type', 'text/event-stream');
      try {
        for (const event of events) {
          const frame =
            `id: ${event.id}\nevent: ${event.event}\n` +
            event.data
              .split('\n')
              .map((line) => 'data: ' + line + '\n')
              .join('') +
            '\n';
          assert.ok(Buffer.byteLength(frame) + response.writableLength <= 1024);
          if (!response.write(frame))
            await once(response, 'drain', { signal: AbortSignal.timeout(1000) });
        }
        response.end();
      } catch {
        response.destroy();
      }
    });
    const native = Fastify({ logger: false });
    await native.register(fastifySSE, {
      heartbeatInterval: 1000,
      maxBufferBytes: 1024,
      serializer: (value: unknown) => {
        assert.equal(typeof value, 'string');
        return value as string;
      },
    });
    native.get('/events', { sse: 'only' }, async (_request, reply) => {
      for (const event of events) await reply.sse.send(event);
      reply.sse.close();
      return reply;
    });
    const read = (url: string) =>
      new Promise<string>((resolve, reject) => {
        const request = get(url, { headers: { accept: 'text/event-stream' } }, (response) => {
          const chunks: Buffer[] = [];
          response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          response.once('error', reject);
          response.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });
        request.once('error', reject);
      });
    try {
      await new Promise<void>((resolve) => reference.listen(0, '127.0.0.1', resolve));
      const address = reference.address();
      assert.ok(address && typeof address === 'object');
      const origin = await native.listen({ host: '127.0.0.1', port: 0 });
      const [actual, expected] = await Promise.all([
        read(origin + '/events'),
        read('http://127.0.0.1:' + address.port),
      ]);
      assert.equal(actual, expected);
      assert.ok(actual.includes('data: \n\n'));
    } finally {
      await native.close();
      reference.closeAllConnections();
      await new Promise<void>((resolve) => reference.close(() => resolve()));
    }
  },
);
