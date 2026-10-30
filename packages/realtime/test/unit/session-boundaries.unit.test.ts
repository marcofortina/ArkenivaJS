// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import type { RealtimeSession } from '../../dist/index.js';
import { SseCursorError } from '../../dist/index.js';
import { fixture, policy } from '../fixture.js';

const aborted = (signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal.aborted) resolve();
    else signal.addEventListener('abort', () => resolve(), { once: true });
  });

test(
  'Native WebSocket sessions reject invalid sends without partial frames and enforce one receive iterator',
  { timeout: 10000 },
  async () => {
    let entered!: (session: RealtimeSession) => void;
    const ready = new Promise<RealtimeSession>((resolve) => {
      entered = resolve;
    });
    const f = await fixture({
      websocketHandlers: {
        async echo(session) {
          entered(session);
          await aborted(session.signal);
        },
      },
    });
    const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token() },
    });
    let frames = 0,
      effects = 0;
    socket.on('message', () => {
      frames++;
    });
    try {
      await once(socket, 'open');
      const session = await ready;
      const message = { channel: 'updates', payload: new Uint8Array([0, 255, 128]), id: 'event_1' };
      for (const options of [
        { timeoutMs: 0 },
        { timeoutMs: 1001 },
        { signal: {} },
        { extra: true },
        Object.defineProperty({}, 'signal', {
          get() {
            effects++;
            return undefined;
          },
        }),
      ])
        await assert.rejects(session.send(message, options as never), {
          code: 'EK_CONFIG_INVALID',
        });
      await assert.rejects(session.send(message, { signal: AbortSignal.abort() }), {
        code: 'EK_ABORTED',
      });
      for (const input of [
        { ...message, channel: '' },
        { ...message, payload: new Uint16Array(1) },
      ])
        await assert.rejects(session.send(input as never), { code: 'EK_CONFIG_INVALID' });
      await assert.rejects(
        session.send({ ...message, id: 'bad cursor' }),
        (error: unknown) => error instanceof SseCursorError && error.reason === 'invalid',
      );
      assert.equal(effects, 0);
      assert.equal(frames, 0);
      const received = once(socket, 'message');
      await session.send(message);
      assert.deepEqual(JSON.parse(String((await received)[0])), {
        channel: 'updates',
        payload: 'AP-A',
        id: 'event_1',
      });
      assert.equal(frames, 1);
      const iterator = session.receive()[Symbol.asyncIterator]();
      assert.throws(() => session.receive(), { code: 'EK_REALTIME_BACKPRESSURE' });
      const next = iterator.next();
      socket.send(JSON.stringify({ channel: 'updates', payload: 'AQ', id: 'event_2' }));
      const value = await next;
      assert.equal(value.done, false);
      assert.deepEqual(value.value, {
        channel: 'updates',
        payload: new Uint8Array([1]),
        id: 'event_2',
      });
      const closed = once(socket, 'close');
      await iterator.return?.();
      await closed;
      await assert.rejects(session.send(message), { code: 'EK_REALTIME_CLOSED' });
    } finally {
      socket.terminate();
      await f.close();
    }
  },
);

test(
  'Native WebSocket heartbeat rejects changed verified tenant or subject and failed reauthorization',
  { timeout: 15000 },
  async () => {
    for (const mode of ['tenant', 'subject', 'failure']) {
      let replacement: string | undefined,
        unavailable = false;
      const f = await fixture({
        policies: { standard: { ...policy, heartbeatMs: 15 } },
        identityAuthority: {
          async authenticate(request, options) {
            if (unavailable) throw new Error('Private reauthorization provider diagnostic');
            return f.app.auth!.tenantFrom(
              await f.app.auth!.verifyBearer(replacement ?? request.headers.authorization, options),
            );
          },
        },
        websocketHandlers: {
          async echo(session) {
            await aborted(session.signal);
          },
        },
      });
      const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
        headers: { authorization: await f.token() },
      });
      try {
        await once(socket, 'open');
        const closed = once(socket, 'close');
        if (mode === 'failure') unavailable = true;
        else
          replacement = await f.token(
            mode === 'tenant' ? 'tenant-b' : 'tenant-a',
            '2m',
            mode === 'subject' ? 'changed-subject' : 'realtime-test-account',
          );
        await closed;
        assert.doesNotMatch(
          f.logs(),
          /Private reauthorization provider diagnostic|changed-subject|tenant-b/,
        );
      } finally {
        socket.terminate();
        await f.close();
      }
    }
  },
);

test(
  'Native WebSocket idle expiry closes the peer and releases handler ownership',
  { timeout: 5000 },
  async () => {
    let finished!: () => void;
    const completed = new Promise<void>((resolve) => {
      finished = resolve;
    });
    const f = await fixture({
      policies: { standard: { ...policy, heartbeatMs: 15, idleTimeoutMs: 45 } },
      websocketHandlers: {
        async echo(session) {
          await aborted(session.signal);
          finished();
        },
      },
    });
    const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token() },
    });
    try {
      await once(socket, 'open');
      await once(socket, 'close');
      await completed;
      await f.service.close();
    } finally {
      socket.terminate();
      await f.close();
    }
  },
);
