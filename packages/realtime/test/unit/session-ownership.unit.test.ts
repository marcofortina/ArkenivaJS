// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { get } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { KitError } from '@arkenivajs/core';
import type { RealtimeSession } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test(
  'SSE shutdown retains a blocked native async generator and rejects its late event until final return',
  { timeout: 10000 },
  async () => {
    let entered!: () => void, release!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    let settled = false,
      returned = 0,
      wire = '';
    const f = await fixture({
      sseSources: {
        events: {
          kind: 'pubsub',
          async *subscribe(context) {
            try {
              entered();
              await hold;
              assert.equal(context.signal.aborted, true);
              settled = true;
              yield {
                id: 'late_1',
                type: 'update',
                data: 'Must never reach the disconnected peer',
              };
            } finally {
              returned++;
            }
          },
        },
      },
    });
    const authorization = await f.token();
    let incoming!: (response: IncomingMessage) => void;
    const responseReady = new Promise<IncomingMessage>((resolve) => {
      incoming = resolve;
    });
    const request = get(
      f.origin + '/events',
      { headers: { authorization, accept: 'text/event-stream' } },
      incoming,
    );
    request.on('error', () => undefined);
    try {
      await started;
      const response = await responseReady;
      assert.equal(response.statusCode, 200);
      response.on('data', (chunk: Buffer) => {
        wire += chunk.toString('utf8');
      });
      const ended = once(response, 'end');
      response.resume();
      let drained = false;
      const closing = f.service.close().then(() => {
        drained = true;
      });
      await delay(5);
      assert.equal(drained, false);
      assert.equal(settled, false);
      assert.equal(returned, 0);
      release();
      await Promise.all([closing, ended]);
      assert.equal(settled, true);
      assert.equal(returned, 1);
      assert.doesNotMatch(wire, /(?:^|\n)(?:data|id|event):|late_1/);
      assert.equal(drained, true);
    } finally {
      release();
      request.destroy();
      await f.close();
    }
  },
);

test(
  'Canceled queued WebSocket sends retain noncooperative authorization work until actual shutdown cleanup',
  { timeout: 10000 },
  async () => {
    let entered!: () => void, release!: () => void, expose!: (session: RealtimeSession) => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    const ready = new Promise<RealtimeSession>((resolve) => {
      expose = resolve;
    });
    let blocked = false,
      settled = false,
      effects = 0,
      frames = 0;
    const f = await fixture({
      identityAuthority: {
        async authenticate(request, options) {
          if (blocked) {
            entered();
            await hold;
            assert.equal(options?.signal?.aborted, true);
            settled = true;
          }
          return f.app.auth!.tenantFrom(
            await f.app.auth!.verifyBearer(request.headers.authorization),
          );
        },
      },
      websocketHandlers: {
        async echo(session) {
          expose(session);
          if (!session.signal.aborted)
            await new Promise<void>((resolve) =>
              session.signal.addEventListener('abort', () => resolve(), { once: true }),
            );
        },
      },
    });
    const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token() },
    });
    socket.on('message', () => {
      frames++;
    });
    try {
      await once(socket, 'open');
      const session = await ready;
      blocked = true;
      const message = { channel: 'updates', payload: new Uint8Array([1, 2, 3]) };
      const first = assert.rejects(
        session.send(message),
        (error: unknown) =>
          error instanceof KitError && ['EK_ABORTED', 'EK_REALTIME_CLOSED'].includes(error.code),
      );
      await started;
      const controller = new AbortController();
      const second = assert.rejects(session.send(message, { signal: controller.signal }), {
        code: 'EK_ABORTED',
      });
      Object.defineProperty(controller.signal, 'removeEventListener', {
        value: () => {
          effects++;
        },
      });
      const closed = once(socket, 'close');
      controller.abort();
      await Promise.all([first, second, closed]);
      assert.equal(settled, false);
      assert.equal(frames, 0);
      let drained = false;
      const closing = f.service.close().then(() => {
        drained = true;
      });
      await delay(5);
      assert.equal(drained, false);
      release();
      await closing;
      assert.equal(settled, true);
      assert.equal(drained, true);
      assert.equal(effects, 0);
      assert.equal(frames, 0);
    } finally {
      release();
      socket.terminate();
      await f.close();
    }
  },
);
