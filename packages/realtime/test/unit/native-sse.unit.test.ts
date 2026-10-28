// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import Fastify from 'fastify';
import { fastifySSE } from '@fastify/sse';

test(
  'The pinned native SSE plugin retains at most one backpressured heartbeat and releases every close listener',
  { timeout: 5000 },
  async () => {
    const server = Fastify({ logger: false });
    await server.register(fastifySSE, { heartbeatInterval: 10, maxBufferBytes: 1024 });
    let heartbeats = 0,
      drainListeners = 0;
    server.get('/events', { sse: 'only' }, async (_request, reply) => {
      const write = reply.raw.write;
      Object.defineProperty(reply.raw, 'write', {
        configurable: true,
        value: (...args: unknown[]) => {
          if (String(args[0]).startsWith(': heartbeat')) {
            heartbeats++;
            Reflect.apply(write, reply.raw, args);
            return false;
          }
          return Reflect.apply(write, reply.raw, args);
        },
      });
      await reply.sse.send({ id: 'ready', data: 'connected' });
      await new Promise<void>((resolve) =>
        reply.sse.onClose(() => {
          drainListeners = reply.raw.listenerCount('drain');
          resolve();
        }),
      );
      // The pending native write removes its drain listener during this same close dispatch.
      await Promise.resolve();
      drainListeners = reply.raw.listenerCount('drain');
      return reply;
    });
    try {
      const origin = await server.listen({ host: '127.0.0.1', port: 0 });
      await new Promise<void>((resolve, reject) => {
        const outgoing = get(
          origin + '/events',
          { headers: { accept: 'text/event-stream' } },
          (response) => {
            response.on('error', () => undefined);
            response.once('data', () => {
              void delay(75)
                .then(() => {
                  const actual = heartbeats;
                  response.destroy();
                  assert.equal(actual, 1);
                  resolve();
                })
                .catch(reject);
            });
          },
        );
        outgoing.once('error', reject);
      });
    } finally {
      await server.close();
    }
    assert.equal(drainListeners, 0);
  },
);

test(
  'The pinned native SSE plugin checks heartbeat bytes against its route budget before writing',
  { timeout: 5000 },
  async () => {
    const server = Fastify({ logger: false });
    await server.register(fastifySSE, { heartbeatInterval: 10, maxBufferBytes: 8 });
    let writes = 0;
    server.get('/events', { sse: 'only' }, async (_request, reply) => {
      reply.sse.sendHeaders();
      Object.defineProperty(reply.raw, 'write', {
        configurable: true,
        value: () => {
          writes++;
          return true;
        },
      });
      await new Promise<void>((resolve) => reply.sse.onClose(resolve));
      return reply;
    });
    try {
      const origin = await server.listen({ host: '127.0.0.1', port: 0 });
      await new Promise<void>((resolve, reject) => {
        const outgoing = get(
          origin + '/events',
          { headers: { accept: 'text/event-stream' } },
          (response) => {
            response.resume();
            response.once('end', resolve);
            response.once('error', reject);
          },
        );
        outgoing.once('error', reject);
      });
      assert.equal(writes, 0);
    } finally {
      await server.close();
    }
  },
);
