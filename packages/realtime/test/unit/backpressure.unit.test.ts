// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'node:http';
import { once } from 'node:events';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { fixture } from '../fixture.js';

test(
  'A real paused WebSocket receiver cannot retain unbounded server output or block stream cleanup',
  { timeout: 10000 },
  async () => {
    let stopped!: () => void;
    const disconnected = new Promise<void>((resolve) => {
      stopped = resolve;
    });
    const f = await fixture({
      policy: { maxConcurrent: 8, timeoutMs: 250 },
      websocketHandlers: {
        async echo(session) {
          session.signal.addEventListener('abort', stopped, { once: true });
          for (let index = 0; index < 10000; index++)
            await session.send({ channel: 'bounded', payload: new Uint8Array(16384) });
          throw new Error('The paused receiver unexpectedly accepted the entire stream');
        },
      },
    });
    let socket: WebSocket | undefined;
    try {
      socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token() },
      });
      await once(socket, 'open');
      socket.pause();
      await disconnected;
      await assert.doesNotReject(f.service.close());
    } finally {
      socket?.terminate();
      await f.close();
    }
  },
);

test(
  'Native SSE write acknowledgement releases on close even when drain never arrives',
  { timeout: 10000 },
  async () => {
    const heldAcknowledgement: Plugin = {
      id: 'held-write-acknowledgement',
      version: '1.0.0',
      capabilities: new Set(),
      dependencies: ['api'],
      init(context) {
        context
          .require<ManagedApiServer>(COMPONENTS.api)
          .native()
          .addHook('onRequest', async (request, reply) => {
            if (request.url !== '/events') return;
            const original = reply.raw.write;
            // Fault injection models the native Writable contract: close can occur without a future drain.
            Object.defineProperty(reply.raw, 'write', {
              configurable: true,
              value: (...args: unknown[]) => {
                Reflect.apply(original, reply.raw, args);
                return false;
              },
            });
          });
      },
      close() {},
    };
    const f = await fixture({}, undefined, [heldAcknowledgement]);
    try {
      const authorization = await f.token();
      await new Promise<void>((resolve, reject) => {
        const request = get(
          f.origin + '/events',
          { headers: { authorization, accept: 'text/event-stream' } },
          (response) => {
            response.on('error', () => undefined);
            response.once('data', () => {
              response.destroy();
              resolve();
            });
          },
        );
        request.once('error', reject);
      });
      await assert.doesNotReject(f.service.close());
    } finally {
      await f.close();
    }
  },
);
