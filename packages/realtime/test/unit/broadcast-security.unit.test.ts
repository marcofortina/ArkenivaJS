// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { MessageBus, MessageEnvelope, Plugin } from '@arkenivajs/core';
import { fixture } from '../fixture.js';

test(
  'Untrusted broker frames cannot inject identity, bypass canonical encoding or exceed the stream byte budget',
  { timeout: 15000 },
  async () => {
    for (const payload of [
      { channel: 'updates', payload: '@@' },
      { channel: 'updates', payload: 'AB' },
      { channel: 'updates', payload: 'aGk', tenantId: 'tenant-b' },
      { channel: 'updates', payload: '', id: 'bad cursor' },
      { channel: '', payload: '' },
      { channel: 'updates', payload: Buffer.alloc(300).toString('base64url') },
    ]) {
      const callbacks: ((message: MessageEnvelope<unknown>) => Promise<void>)[] = [];
      const backend: MessageBus = {
        async publish() {
          return { messageId: 'fixture', acknowledged: false };
        },
        async subscribe<T>(
          _topic: string,
          handler: (message: MessageEnvelope<T>) => Promise<void>,
        ) {
          callbacks.push(handler as (typeof callbacks)[number]);
          return { async close() {} };
        },
      };
      const broker: Plugin = {
        id: 'messaging',
        version: '1.0.0',
        capabilities: new Set(['messaging']),
        init(context) {
          context.provide(COMPONENTS.messaging, backend);
        },
        close() {},
      };
      const f = await fixture(
        {
          pubsub: { provider: 'nats', connectionName: 'messaging' },
          policy: { maxConcurrent: 8, timeoutMs: 1000, maxInputBytes: 128 },
        },
        undefined,
        [broker],
      );
      const sockets: WebSocket[] = [];
      try {
        for (const tenant of ['tenant-a', 'tenant-b']) {
          const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
            headers: { authorization: await f.token(tenant) },
          });
          sockets.push(socket);
          await once(socket, 'open');
        }
        const closed = once(sockets[0]!, 'close');
        let leaked = false;
        sockets[1]!.on('message', () => {
          leaked = true;
        });
        await callbacks[0]!({ messageId: 'fixture', topic: 'ignored-untrusted-topic', payload });
        await closed;
        assert.equal(leaked, false);
        assert.equal(sockets[1]!.readyState, WebSocket.OPEN);
      } finally {
        for (const socket of sockets) socket.terminate();
        await f.close();
      }
    }
  },
);

test('Publication requires configured shared transport and sanitizes transport failures and cancellation', async () => {
  const unavailable = await fixture();
  try {
    const tenant = unavailable.app.auth!.tenantFrom(
      await unavailable.app.auth!.verifyBearer(await unavailable.token()),
    );
    await assert.rejects(unavailable.service.publish('updates', new Uint8Array(), tenant), {
      code: 'EK_UNSUPPORTED_CAPABILITY',
    });
    for (const options of [
      { timeoutMs: 0 },
      { timeoutMs: 1001 },
      { signal: {} },
      { unknown: true },
    ])
      await assert.rejects(
        unavailable.service.publish('updates', new Uint8Array(), tenant, options as never),
        { code: 'EK_CONFIG_INVALID' },
      );
    await assert.rejects(
      unavailable.service.publish('updates', new Uint8Array(), tenant, {
        signal: AbortSignal.abort(),
      }),
      { code: 'EK_ABORTED' },
    );
    await unavailable.service.close();
    await assert.rejects(unavailable.service.publish('updates', new Uint8Array(), tenant), {
      code: 'EK_REALTIME_CLOSED',
    });
  } finally {
    await unavailable.close();
  }
  const backend: MessageBus = {
    async publish() {
      throw new Error('private-broker-credential');
    },
    async subscribe() {
      throw new Error('private-broker-credential');
    },
  };
  const broker: Plugin = {
    id: 'messaging',
    version: '1.0.0',
    capabilities: new Set(['messaging']),
    init(context) {
      context.provide(COMPONENTS.messaging, backend);
    },
    close() {},
  };
  const f = await fixture(
    { pubsub: { provider: 'nats', connectionName: 'messaging' } },
    undefined,
    [broker],
  );
  try {
    const tenant = f.app.auth!.tenantFrom(await f.app.auth!.verifyBearer(await f.token()));
    await assert.rejects(
      f.service.publish('updates', new Uint8Array(), tenant, { timeoutMs: 500 }),
      (error: unknown) =>
        error instanceof Error &&
        !error.message.includes('private') &&
        (error as { code?: string }).code === 'EK_BACKEND_UNAVAILABLE',
    );
    const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token() },
    });
    socket.on('error', () => undefined);
    const response = await new Promise<number>((resolve) =>
      socket.once('unexpected-response', (_request, incoming) => {
        incoming.resume();
        socket.terminate();
        resolve(incoming.statusCode!);
      }),
    );
    assert.equal(response, 503);
    assert.ok(!f.logs().includes('private-broker-credential'));
  } finally {
    await f.close();
  }
});
