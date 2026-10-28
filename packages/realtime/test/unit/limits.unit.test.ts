// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import WebSocket from 'ws';
import { realtimePlugin } from '../../dist/index.js';
import { fixture, policy } from '../fixture.js';

test('Realtime startup bounds reject invalid policies, unsafe paths, catalog references and accessors', () => {
  const base = {
    routes: [] as const,
    websocketHandlers: {},
    sseSources: {},
    policies: {},
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  };
  for (const timeoutMs of [0, -1, 1.5, NaN, Infinity, 30001])
    assert.throws(() => realtimePlugin({ ...base, policy: { ...base.policy, timeoutMs } }), {
      code: 'EK_CONFIG_INVALID',
    });
  for (const change of [
    { requireAuth: false },
    { heartbeatMs: 0 },
    { maxBufferBytes: 1 },
    { heartbeatMs: policy.idleTimeoutMs },
    { maxConnectionsPerTenant: 0 },
  ])
    assert.throws(
      () => realtimePlugin({ ...base, policies: { standard: { ...policy, ...change } as never } }),
      { code: 'EK_CONFIG_INVALID' },
    );
  for (const path of [
    '/unsafe/*',
    '/unsafe/:id',
    '/unsafe?query',
    '/unsafe%2fpath',
    '/unsafe/../path',
    '/',
  ])
    assert.throws(
      () =>
        realtimePlugin({
          ...base,
          policies: { standard: policy },
          websocketHandlers: { echo: async () => {} },
          routes: [{ kind: 'websocket', path, handlerKey: 'echo', policyKey: 'standard' }],
        }),
      { code: 'EK_CONFIG_INVALID' },
    );
  let read = false;
  assert.throws(
    () =>
      realtimePlugin({
        ...base,
        get allowedOrigins() {
          read = true;
          return [];
        },
      }),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(read, false);
  assert.throws(() =>
    realtimePlugin({ ...base, allowedOrigins: ['https://browser.invalid/path'] }),
  );
  assert.throws(
    () =>
      realtimePlugin({ ...base, pubsub: { provider: 'local' as never, connectionName: 'test' } }),
    { code: 'EK_CONFIG_INVALID' },
  );
});

test(
  'Malformed and globally oversized WebSocket frames close without reaching the application handler',
  { timeout: 10000 },
  async () => {
    const f = await fixture({ policy: { maxConcurrent: 8, timeoutMs: 1000, maxInputBytes: 128 } });
    try {
      const authorization = await f.token();
      for (const frame of [
        Buffer.from([0xff]),
        '{"channel":"event","payload":"@@"}',
        '{"channel":"event","payload":"aGk=","tenant":"spoofed"}',
        JSON.stringify({ channel: 'event', payload: 'eA'.repeat(100) }),
      ]) {
        const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
          headers: { authorization },
        });
        await once(socket, 'open');
        const closed = once(socket, 'close');
        let messages = 0;
        socket.on('message', () => {
          messages++;
        });
        socket.send(frame);
        await closed;
        assert.equal(messages, 0);
      }
    } finally {
      await f.close();
    }
  },
);

test(
  'Global output bounds reject an otherwise permitted WebSocket frame and discard no partial message',
  { timeout: 5000 },
  async () => {
    const f = await fixture({ policy: { maxConcurrent: 8, timeoutMs: 1000, maxOutputBytes: 32 } });
    const socket = new WebSocket(f.origin.replace('http:', 'ws:') + '/socket', {
      headers: { authorization: await f.token() },
    });
    try {
      await once(socket, 'open');
      let count = 0;
      socket.on('message', () => {
        count++;
      });
      const closed = once(socket, 'close');
      socket.send('{"channel":"updates","payload":"aGk"}');
      await closed;
      assert.equal(count, 0);
    } finally {
      socket.terminate();
      await f.close();
    }
  },
);
